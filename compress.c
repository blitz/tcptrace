/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
 *	Ohio University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the
 * distribution, and (3) all advertising materials mentioning features
 * or use of this software display the following acknowledgment:
 * ``This product includes software developed by the Ohio University
 * Internetworking Research Laboratory.''  Neither the name of the
 * University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific
 * prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 */
static char const copyright[] =
    "@(#)Copyright (c) 1997 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "$Id$";


#include "tcptrace.h"
#include "compress.h"
#include <sys/wait.h>


/* local routines */
static char *FindBinary(char *binname);
static struct comp_formats *WhichFormat(char *filename);
static FILE *CompSaveHeader(char *filename, struct comp_formats *pf);
static int CompOpenPipe(char *filename, struct comp_formats *pf);


/* local globals */
static int header_length = -1;
static Bool is_compressed = FALSE;



static char *FindBinary(
    char *binname)
{
    char *path;
    char *pch;
    char *pch_colon;
    static char abspath[256];

    /* quick check for absolute path */
    if (*binname == '/') {
	if (access(binname,X_OK) == 0) {
	    if (debug>1)
		fprintf(stderr,"FindBinary: abs path '%s' is OK\n", binname);
	    return(binname);
	} else {
	    if (debug>1)
		fprintf(stderr,"FindBinary: abs path '%s' not found\n", binname);
	    return(NULL);
	}
    }

    path = getenv("PATH");
    if (path == NULL) {
	if (debug)
	    fprintf(stderr,"FindBinary: couldn't get PATH envariable\n");
	return(NULL);
    }

    path = strdup(path);
    pch = path;

    while (pch && *pch) {
	pch_colon = strchr(pch,':');
	if (pch_colon)
	    *pch_colon = '\00';

	sprintf(abspath,"%s/%s",pch,binname);

	if (debug>1)
	    fprintf(stderr,"Checking for binary '%s'\n", abspath);
	if (access(abspath,X_OK) == 0) {
	    if (debug>1)
		fprintf(stderr,"FindBinary: found binary '%s'\n", abspath);
	    return(abspath);
	}

	if (pch_colon)
	    pch = pch_colon+1;
	else
	    pch = NULL;
    }

    if (debug)
	fprintf(stderr,"FindBinary: couldn't find binary '%s' in PATH\n",
		binname);

    return(NULL);
}
 


static struct comp_formats *
WhichFormat(
    char *filename)
{
    static struct comp_formats *pf_cache = NULL;
    static char *pf_file_cache = NULL;
    int len;
    int lens;
    int i;

    /* check the "cache" :-) */
    if (pf_file_cache && (strcmp(filename,pf_file_cache) == 0)) {
	return(pf_cache);
    }

    len = strlen(filename);

    for (i=0; i < NUM_COMP_FORMATS; ++i) {
	struct comp_formats *pf = &supported_comp_formats[i];

	if (debug>1)
	    fprintf(stderr,"Checking for suffix match '%s' against '%s' (%s)\n",
		    filename,pf->comp_suffix,pf->comp_bin);
	/* check for suffix match */
	lens = strlen(pf->comp_suffix);
	if (strcmp(filename+len-lens, pf->comp_suffix) == 0) {
	    if (debug>1)
		fprintf(stderr,"Suffix match!   '%s' against '%s'\n",
			filename,pf->comp_suffix);
	    /* stick it in the cache */
	    pf_file_cache = strdup(filename);
	    pf_cache = pf;
	    is_compressed = TRUE;

	    /* and tell the world */
	    return(pf);
	}
    }

    pf_file_cache = strdup(filename);
    pf_cache = NULL;
    is_compressed = FALSE;

    if (debug)
	fprintf(stderr,"WhichFormat: failed to find compression format for file '%s'\n",
		filename);

    return(NULL);
}



static FILE *
CompReopenFile(
    char *filename)
{
    char buf[COMP_HDR_SIZE];
    struct comp_formats *pf = WhichFormat(filename);
    int len;
    int fd;
    long pos;

    if (debug>1)
	fprintf(stderr,"CompReopenFile('%s') called\n", filename);

    /* we need to switch from the header file to a pipe connected */
    /* to a process.  Find out how far we've read from the file */
    /* so far... */
    pos = ftell(stdin);

    /* open a pipe to the original (compressed) file */
    fd = CompOpenPipe(filename,pf);
    if (fd == -1)
	return(NULL);

    /* erase the file buffer and reposition to the front */
#ifdef HAVE_FPURGE
    /* needed for NetBSD and FreeBSD (at least) */
    fpurge(stdin);		/* discard input buffer */
#else /* HAVE_FPURGE */
    fflush(stdin);		/* discard input buffer */
#endif /* HAVE_FPURGE */
    rewind(stdin);

    /* yank the FD out from under stdin and point to the pipe */
    dup2(fd,0);

    /* skip forward in the stream to the same place that we were in */
    /* for the header file */
    len = fread(buf,1,pos,stdin);
    if ((len == 0) && ferror(stdin)) {
	perror("read forward in stdin");
	exit(-1);
    }

    /* OK, I guess we're all set... */
    return(stdin);
}




static FILE *
CompSaveHeader(
    char *filename,
    struct comp_formats *pf)
{
    FILE *f_stream;
    FILE *f_file;
    char buf[COMP_HDR_SIZE];
    char *tempfile;
    int len;
    int fd;

    fd = CompOpenPipe(filename,pf);
    if (fd == -1)
	return(NULL);

    /* get a name for a temporary file to store the header in */
    tempfile = tempnam("/tmp/","trace_hdr");

    /* open the file */
    if ((f_file = fopen(tempfile,"w+")) == NULL) {
	perror(tempfile);
	exit(-1);
    }

    /* connect a stdio stream to the pipe */
    if ((f_stream = fdopen(fd,"r")) == NULL) {
	perror("open pipe stream for header");
	exit(-1);
    }

    /* just grab the first X bytes and stuff into a temp file */
    len = fread(buf,1,COMP_HDR_SIZE,f_stream);
    if ((len == 0) && ferror(f_stream)) {
	perror("read pipe stream for header");
	exit(-1);
    }

    if (len == 0) {
	/* EOF, failure */
	return(NULL);
    }

    header_length = len;
    if (debug>1)
	fprintf(stderr,"Saved %d bytes from stream into temp header file '%s'\n",
		len, tempfile);

    /* save the header into a temp file */
    len = fwrite(buf,1,len,f_file);
    if ((len == 0) && ferror(f_file)) {
	perror("write file stream for header");
	exit(-1);
    }

    if (debug>1)
	fprintf(stderr,"Saved the file header into temp file '%s'\n",
		tempfile);


    /* OK, we have the header, close the stream and file */
    fclose(f_stream);
    fclose(f_file);

    /* re-open the file as stdin */
    if ((freopen(tempfile,"r",stdin)) == NULL) {
	perror("tempfile");
	exit(-1);
    }

    /* now that it's open, just delete the file */
    /* it should stay on the disk until closed... */
    unlink(tempfile);
    
    return(stdin);
}



static int
CompOpenPipe(
    char *filename,
    struct comp_formats *pf)
{
    int fdpipe[2];
    char *abspath;
    int pid;
    int i;
    char *args[COMP_MAX_ARGS];

    if (debug>1)
	fprintf(stderr,"CompOpenPipe('%s') called\n", filename);

    abspath = FindBinary(pf->comp_bin);
    if (!abspath) {
	fprintf(stderr,
		"Compression: failed to find binary for '%s' needed to uncompress file\n",
		pf->comp_bin);
	fprintf(stderr,
		"According to my configuration, I need '%s' to decode files of type\n",
		pf->comp_bin);
	fprintf(stderr, "%s\n", pf->comp_descr);
	exit(-1);
    }

    /* save the path for later... */
    pf->comp_bin = strdup(abspath);

    /* filter args */
    for (i=0; i < COMP_MAX_ARGS; ++i) {
	args[i] = pf->comp_args[i];
	if (!args[i])
	    break;
	if (strcmp(pf->comp_args[i],"%s") == 0)
	    args[i] = filename;
    }
		      

    if (pipe(fdpipe) == -1) {
	perror("pipe");
	exit(-1);
    }

    pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(-1);
    }
    if (pid == 0) {
	/* child */
	dup2(fdpipe[1],1);  /* redirect child's stdout to pipe */

	for (i=3; i < 100; ++i) close(i);

	if (debug>1) {
	    fprintf(stderr,"Execing %s", abspath);
	    for (i=1; args[i]; ++i)
		fprintf(stderr," %s", args[i]);
	    fprintf(stderr,"\n");
	}
	

	execv(abspath,args);
	fprintf(stderr,"Exec of '%s' failed\n", abspath);
	perror(abspath);
	exit(-1);
    }

    close(fdpipe[1]);
    return(fdpipe[0]);
}





FILE *
CompOpenHeader(
    char *filename)
{
    FILE *f;
    struct comp_formats *pf;

    /* see if it's a supported compression file */
    pf = WhichFormat(filename);

    /* if no compression found, just open the file */
    if (pf == NULL) {
	if (freopen(filename,"r",stdin) == NULL) {
	    perror(filename);
	    return(NULL);
	}
	return(stdin);
    }

    /* open the file through compression */
    if (debug)
	printf("Decompressing file of type '%s' using program '%s'\n",
	       pf->comp_descr, pf->comp_bin);
    else
	printf("Decompressing file using '%s'\n", pf->comp_bin);

    f = CompSaveHeader(filename,pf);

    if (!f) {
	fprintf(stderr,"Decompression failed for file '%s'\n", filename);
	exit(-1);
    }

    return(f);
}


FILE *
CompOpenFile(
    char *filename)
{
    if (debug>1)
	fprintf(stderr,"CompOpenFile('%s') called\n", filename);

    /* if it isn't compressed, just leave it at stdin */
    if (!is_compressed)
	return(stdin);

    /* if the header we already saved is the whole file, it must be */
    /* short, so just read from the file */
    if (header_length < COMP_HDR_SIZE) {
	if (debug>1)
	    fprintf(stderr,"CompOpenFile: still using header file, short file...\n");
	return(stdin);
    }

    /* otherwise, there's more than we saved, we need to re-open the pipe */
    /* and re-attach it to stdin */
    return(CompReopenFile(filename));
}


void
CompCloseFile(
    char *filename)
{
/*     fclose(stdin); */

    /* in case we have a child still in the background */
    wait(0);

    /* zero out some globals */
    header_length = -1;
}


int
CompIsCompressed(void)
{
    return(is_compressed);
}


void
CompFormats(void)
{
    int i;
    
    fprintf(stderr,"Supported Compression Formats:\n");
    fprintf(stderr,"\tSuffix  Description           Uncompress Command\n");
    fprintf(stderr,"\t------  --------------------  --------------------------\n");

    for (i=0; i < NUM_COMP_FORMATS; ++i) {
	int arg;
	struct comp_formats *pf = &supported_comp_formats[i];

	fprintf(stderr,"\t%6s  %-20s  %s",
		pf->comp_suffix,
		pf->comp_descr,
		pf->comp_bin);
	for (arg=1; pf->comp_args[arg]; ++arg)
	    fprintf(stderr," %s", pf->comp_args[arg]);
	fprintf(stderr,"\n");
    }
}
