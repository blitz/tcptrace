/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
 *	Ohio University.
 *
 * ---
 * 
 * Starting with the release of tcptrace version 6 in 2001, tcptrace
 * is licensed under the GNU General Public License (GPL).  We believe
 * that, among the available licenses, the GPL will do the best job of
 * allowing tcptrace to continue to be a valuable, freely-available
 * and well-maintained tool for the networking community.
 *
 * Previous versions of tcptrace were released under a license that
 * was much less restrictive with respect to how tcptrace could be
 * used in commercial products.  Because of this, I am willing to
 * consider alternate license arrangements as allowed in Section 10 of
 * the GNU GPL.  Before I would consider licensing tcptrace under an
 * alternate agreement with a particular individual or company,
 * however, I would have to be convinced that such an alternative
 * would be to the greater benefit of the networking community.
 * 
 * ---
 *
 * This file is part of Tcptrace.
 *
 * Tcptrace was originally written and continues to be maintained by
 * Shawn Ostermann with the help of a group of devoted students and
 * users (see the file 'THANKS').  The work on tcptrace has been made
 * possible over the years through the generous support of NASA GRC,
 * the National Science Foundation, and Sun Microsystems.
 *
 * Tcptrace is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tcptrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tcptrace (in the file 'COPYING'); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
static char const rcsid[] =
    "$Header$";


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
static int child_pid = -1;
static char *tempfile;
int posn;


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

	snprintf(abspath,sizeof(abspath),"%s/%s",pch,binname);

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
    int len;
    int fd;

    fd = CompOpenPipe(filename,pf);
    if (fd == -1)
	return(NULL);

#ifdef HAVE_MKSTEMP
    {
	/* From Mallman, supposed to be "safer" */
	int fd;
	extern int mkstemp(char *template);

	/* grab a writable string to keep picky compilers happy */
	tempfile = strdup("/tmp/trace_hdrXXXXXXXX");

	/* create a temporary file name and open it */
	if ((fd = mkstemp(tempfile)) == -1) {
	    perror("template");
	    exit(-1);
	}

	/* convert to a stream */
	f_file = fdopen(fd,"w");
    }
#else /* HAVE_MKSTEMP */
    /* get a name for a temporary file to store the header in */
    tempfile = tempnam("/tmp/","trace_hdr");

    /* open the file */
    if ((f_file = fopen(tempfile,"w+")) == NULL) {
	perror(tempfile);
	exit(-1);
    }

#endif /* HAVE_MKSTEMP */


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

    return(stdin);
}



static int
CompOpenPipe(
    char *filename,
    struct comp_formats *pf)
{
    int fdpipe[2];
    char *abspath;
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
		      

    if (Mfpipe(fdpipe) == -1) {
	perror("pipe");
	exit(-1);
    }

#ifdef __VMS
    child_pid = vfork();
#else
    child_pid = fork();
#endif
    if (child_pid == -1) {
	perror("fork");
	exit(-1);
    }
    if (child_pid == 0) {
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

#ifdef __WIN32
    if(pf != NULL) {
       fprintf(stderr, "\nError: windows version of tcptrace does not support\nreading compressed dump files. Uncompress the file\nmanually and try again. Sorry!\n");
       return((FILE *)-1);
    }
    return(NULL);
#endif /* __WIN32 */   
   
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
	 posn=ftell(stdin);
	 if (posn < 0) {
	      perror("CompOpenFile : ftell failed");
	      exit(-1);
	 }
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
    FILE *f_return;

    /* On coming in, here's what's in the FDs: */
    /*   stdin: 	has the header file open */
    /*   f_stdin_file:	holds the rest of the stream */

    if (Mfpipe(fdpipe) == -1) {
	perror("pipe");
	exit(-1);
    }
    /* remember: fdpipe[0] is for reading, fdpipe[1] is for writing */

#ifdef __VMS
    child_pid = vfork();
#else
    child_pid = fork();
#endif
    if (child_pid == -1) {
	perror("fork");
	exit(-1);
    }
    if (child_pid == 0) {
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
		child_pid);

    /* clean up the fd's */
    close(fdpipe[1]);
    // Now, we shall purge our old STDIN stream buffer, and point it to the
    // read end of the pipe, fdpipe[0]
    
#ifdef HAVE_FPURGE     
     fpurge(stdin); // needed for NetBSD/FreeBSD
#else
     fflush(stdin);
#endif
     clearerr(stdin);
     
     if (dup2(fdpipe[0],0)==-1) {
	  perror("PipeHelper : dup2 failed in parent");
	  exit(-1);
     }
     
    /* make a stream attached to the PIPE and return it */
    f_return = fdopen(fdpipe[0],"r");
    if (f_return == NULL) {
	perror("PipeHelper : fdopen on pipe for reading");
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

    // Fix the file synchronization problems and undefined behavior exhibited
    // by fread() in managing its buffers, when stdin is opened by both the
    // parent and child processes.
    // In the child process (where we are currently executing), close and 
    // re-open the temporary file currently opened as stdin, in which the 
    // first COMP_HDR_SIZE bytes of data were stored. The current file pointer
    // position in the file was stored in the global variable posn.

    if (fclose(f_header)<0)
	  perror("PipeFitting : fclose failed");
     
    if ((f_header=fopen(tempfile,"r"))==NULL) {
	 perror("PipeFitting : fopen of tempfile failed");
	 exit(-1);
    }

    if (fread(buf,1,posn,f_header)!=posn) {
	 perror("PipeFitting : fread failed");
	 exit(-1);
    }
     
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

    // We are done with the temporary file. Time to close and unlink it.
    if (fclose(f_header)<0) 
	  perror("PipeFitting : fclose failed");
     
    if (unlink(tempfile)<0)
	  perror("PipeFitting : unlink of tempfile failed");
     
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
    /* Hmmm... this was commented out, I wonder why? */
/*     fclose(stdin); */

    /* if we have a child, make sure it's dead */
    if (child_pid != -1) {
	kill(child_pid,SIGTERM);
	child_pid = -1;
    }

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
