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
    "@(#)Copyright (c) 1998 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "$Id$";


#include "tcptrace.h"
#include "compress.h"
#include <sys/wait.h>

/*
 * OK, this stuff is a little complicated.  Here's why:
 * 1) the routines that examine the file to see if it's of
 *    a particular type want a real file that they can do
 *    a "seek" on.  Seeking backwards won't work on a stream
 * 2) What I do for compressed files is to decompress twice:
 *    - The first time I just save the first COMP_HDR_SIZE bytes
 *      into a temporary file and then stop the decompression.
 *      I then use that file to determine that file type
 *    - After I know the file type, I restart the decompression
 *      and reconnect the decompress pipe to stdin
 * 3) If the "file" input _IS_ standard input, then it's harder, 
 *    because I can't restart it.  In that case, I use a helper process
 *    that reads the rest of the header file and then starts reading
 *    the rest of the data from standard input.  It's slightly inefficient
 *    because of the extra process, but I don't know a way around...
 */


/* local routines */
static char *FindBinary(char *binname);
static struct comp_formats *WhichFormat(char *filename);
static FILE *CompSaveHeader(char *filename, struct comp_formats *pf);
static int CompOpenPipe(char *filename, struct comp_formats *pf);
static FILE *PipeHelper(void);
static void PipeFitting(FILE *f_pipe, FILE *f_header, FILE *f_stdin);


/* local globals */
static int header_length = -1;
static Bool is_compressed = FALSE;
static FILE * f_orig_stdin = NULL;



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
    if (debug>1)
	fprintf(stderr,"CompReopenFile: current file position is %ld\n", pos);

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


    /* OK, we have the header, close the file */
    fclose(f_file);

    /* if it's stdin, make a copy for later */
    if (FileIsStdin(filename)) {
	f_orig_stdin = f_stream;  /* remember where it is */
    } else {
	fclose(f_stream);
    }

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

    /* short hand if it's just reading from standard input */
    if (FileIsStdin(filename)) {
	return(dup(0));  /* 0: standard input */
    }

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

	/* close all other FDs - lazy, but close enough for our purposes  :-) */
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

    /* short hand if it's just reading from standard input */
    if (FileIsStdin(filename)) {
	is_compressed = TRUE;	/* pretend that it's compressed */
	return(CompSaveHeader(filename,NULL));
    }

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
    if (debug>1)
	printf("Decompressing file of type '%s' using program '%s'\n",
	       pf->comp_descr, pf->comp_bin);
    else if (debug)
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

    /* if we're just reading from standard input, we'll need some help because */
    /* part of the input is in a file and the rest is still stuck in a pipe */
    if (FileIsStdin(filename)) {
	return(PipeHelper());
    }

    /* otherwise, there's more than we saved, we need to re-open the pipe */
    /* and re-attach it to stdin */
    return(CompReopenFile(filename));
}


/* return a FILE * that fill come from a helper process */
FILE *
PipeHelper(void)
{
    int fdpipe[2];
    int pid;
    FILE *f_return;

    /* On coming in, here's what's in the FDs: */
    /*   stdin: 	has the header file open */
    /*   f_stdin_file:	holds the rest of the stream */

    if (pipe(fdpipe) == -1) {
	perror("pipe");
	exit(-1);
    }
    /* remember: fdpipe[0] is for reading, fdpipe[1] is for writing */

    pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(-1);
    }
    if (pid == 0) {
	/* be the helper process */
	FILE *f_pipe;

	/* attach a stream to the pipe connection */
	f_pipe = fdopen(fdpipe[1],"w");
	if (f_pipe == NULL) {
	    perror("fdopen on pipe for writing");
	    exit(-1);
	}

	/* connect the header file and stream to the pipe */
	PipeFitting(f_pipe, stdin, f_orig_stdin);

	/* OK, both empty, we're done */
	if (debug>1)
	    fprintf(stderr,
		    "PipeHelper(%d): all done, exiting\n", (int)getpid());
	    
	exit(0);
    }

    /* I'm still the parent */
    if (debug>1)
	fprintf(stderr,
		"PipeHelper: forked off child %d to deal with stdin\n",
		pid);

    /* clean up the fd's */
    close(fdpipe[1]);
    fclose(stdin);

    /* make a stream attached to the PIPE and return it */
    f_return = fdopen(fdpipe[0],"r");
    if (f_return == NULL) {
	perror("fdopen on pipe for reading");
	exit(-1);
    }
    return(f_return);
}


static void
PipeFitting(
    FILE *f_pipe,
    FILE *f_header,
    FILE *f_orig_stdin)
{
    char buf[4096];		/* just a big buffer */
    int len;

    /* read from f_header (the file) until empty */
    while (1) {
	/* read some more data */
	len = fread(buf,1,sizeof(buf),f_header);
	if (len == 0)
	    break;
	if (len < 0) {
	    perror("fread from f_header");
	    exit(0);
	}

	if (debug>1)
	    fprintf(stderr,
		    "PipeFitting: read %d bytes from header file\n", len);

	/* send those bytes to the pipe */
	if (fwrite(buf,1,len,f_pipe) != len) {
	    perror("fwrite on pipe");
	    exit(-1);
	}
    }

    if (debug>1)
	fprintf(stderr,
		"PipeFitting: header file empty, switching to old stdin\n");

    /* OK, the file is empty, switch back to the stdin stream */
    while (1) {
	/* read some more data */
	len = fread(buf,1,sizeof(buf),f_orig_stdin);
	if (len == 0)
	    break;
	if (len < 0) {
	    perror("fread from f_orig_stdin");
	    exit(0);
	}

	if (debug>1)
	    fprintf(stderr,
		    "PipeFitting: read %d bytes from f_orig_stdin\n", len);

	/* send those bytes to the pipe */
	if (fwrite(buf,1,len,f_pipe) != len) {
	    perror("fwrite on pipe");
	    exit(-1);
	}
    }
}
    



void
CompCloseFile(
    char *filename)
{
/*     fclose(stdin); */

    /* in case we have children child still in the background */
    while (wait(0) != -1)
	; /* nothing */

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


/* does the file name "filename" refer to stdin rather than a real file? */
/* (in case I need to extend this definition someday) */
Bool
FileIsStdin(
    char *filename)
{
    if (strcmp(filename,"stdin") == 0)
	return(1);
    if (strcmp(filename,"stdin.gz") == 0)
	return(1);
    return(0);
}
