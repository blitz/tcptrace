/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
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
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";


/* 
 * tcptrace.c - turn protocol monitor traces into xplot
 * 
 * this set of functions allows a user to open "many files"
 * dispite the open file max limit.   (Uses LRU)
 * 
 * Author:	Shawn Ostermann
 * Date:	Tue Nov  1, 1994
 */

#include <errno.h>


struct mfile {
    FILE *stream;
    char *fname;
    MFILE *next;
    MFILE *prev;
    long fptr;
};


/* local static routines */
static void Mcheck(MFILE *pmf);
static void Mfopen_internal(MFILE *pmf, char *mode);
static void Mf_totail(MFILE *pmf, MFILE *ptail);
static void Mf_unlink(MFILE *pmf);
static void M_closeold(void);
static void M_mkdirp(char *directory);


/* head and tail of LRU open file list */
MFILE mf_head;  /* LEAST recently used */
MFILE mf_tail;  /* MOST recently used */

MFILE mfc_head;  /* closed files, LEAST recently closed */
MFILE mfc_tail;  /* closed files, MOST recently closed */


void
Minit(void)
{
    mf_head.next = &mf_tail;
    mf_tail.prev = &mf_head;
    mf_head.fname = "HEAD";
    mf_tail.fname = "TAIL";

    mfc_head.next = &mfc_tail;
    mfc_tail.prev = &mfc_head;
    mfc_head.fname = "CLOSED HEAD";
    mfc_tail.fname = "CLOSED TAIL";
}




MFILE *
Mfopen(
    char *fname,
    char *mode)
{
    MFILE *pmf;
    char *directory;
    char *prefix;
	int len;

    if ((strcmp(mode,"w") != 0) && (strcmp(mode,"a") != 0)){
	fprintf(stderr,"Sorry, Mfopen works only for mode \"w\" or \"a\"\n");
	exit(-1);
    }

    pmf = (MFILE *) MallocZ(sizeof(MFILE));

    /* use the directory specified by the user, if requested */
    if (output_file_dir == NULL)
	directory = "";
    else {
	directory = ExpandFormat(output_file_dir);
	M_mkdirp(directory);
    }

    /* attach a filename prefix, if the user asked for one */
    if (output_file_prefix == NULL)
	prefix = "";
    else
	prefix = ExpandFormat(output_file_prefix);


	len=strlen(fname)+strlen(directory)+strlen(prefix)+2;
			/* 2: for the slash and null */

    pmf->fname = MallocZ(len);

    snprintf(pmf->fname,len,"%s%s%s%s",
	    directory,
	    (*directory)?"/":"",
	    prefix,
	    fname);

    if (strcmp(mode,"w") == 0)
	Mfopen_internal(pmf,"w+");
    else if (strcmp(mode,"a") == 0)
	Mfopen_internal(pmf,"a+");
    else {
	fprintf(stderr,"Mfopen: internal file mode inconsistancy\n");
	exit(10);
    }

    /* put at the tail of the LRU list */
    Mf_totail(pmf,&mf_tail);

    return(pmf);
}


/* not really an mfiles thing, but works even when we're out of fd's */
int
Mfpipe(
    int pipes[2])
{
    int i;

    for (i=0; i <= 2; ++i) {
	if (pipe(pipes) == 0)
	    return(0);

	if (errno != EMFILE) {
	    perror("pipe");
	    exit(-1);
	}

	M_closeold();
    }

    fprintf(stderr,"mfpipe - internal error, couldn't get pipes?\n");
    exit(-1);
}


int
Mfileno(
    MFILE *pmf)
{
    /* Warning, I'll GIVE you the fd, but I won't guarantee that it'll stay */
    /* where you want it if you call my functions back!!! */

    Mcheck(pmf);
    return(fileno(pmf->stream));
}




int
Mvfprintf(
    MFILE *pmf,
    char *format,
    va_list ap)
{
    int ret;

    Mcheck(pmf);
    ret = vfprintf(pmf->stream,format,ap);

    return(ret);
}



int
Mfprintf(
    MFILE *pmf,
    char *format,
     ...)
{
    va_list ap;
    int ret;

    va_start(ap,format);

    Mcheck(pmf);
    ret = vfprintf(pmf->stream,format,ap);

    va_end(ap);

    return(ret);
}


long
Mftell(
    MFILE *pmf)
{
    Mcheck(pmf);
    return(ftell(pmf->stream));
}


int
Mfseek(
    MFILE *pmf,
    long offset,
    int ptrname)
{
    Mcheck(pmf);
    return(fseek(pmf->stream, offset, ptrname));
}


int
Mfwrite(
    void *buf,
    u_long size,
    u_long nitems,
    MFILE *pmf)
{
    Mcheck(pmf);
    return(fwrite(buf,size,nitems,pmf->stream));
}


int
Mfclose(
    MFILE *pmf)
{
    int ret;

    if (debug>1)
	fprintf(stderr,"Mfclose: called for file '%s'\n", pmf->fname);
	
    Mcheck(pmf);
    ret=fclose(pmf->stream);
    pmf->stream = NULL;
    return(ret);
}


int
Mfflush(
    MFILE *pmf)
{
    Mcheck(pmf);
    return(fflush(pmf->stream));
}



static void
Mfopen_internal(
    MFILE *pmf,
    char *mode)
{
    FILE *stream;
    
    stream = fopen(pmf->fname,mode);

    if (stream == NULL) {

	if (errno != EMFILE) {
	    perror(pmf->fname);
	    exit(-1);
	}

	M_closeold();

	/* now, try again */
	stream = fopen(pmf->fname,mode);
	if (stream == NULL) {
	    perror("fopen (second try)");
	    exit(-1);
	}
    }

    pmf->stream = stream;

    /* seek back to where we were last time, if this was previously opened */
    if (pmf->fptr != 0) {
	if (fseek(stream, pmf->fptr, SEEK_SET) != 0) {
	    perror("fseek");
	    exit(-1);
	}
    }

    return;
}

static void
M_closeold(void)
{
    MFILE *closehim;

    /* OK, close a file we haven't used for a while */
    closehim = mf_head.next;
    closehim->fptr = ftell(closehim->stream);  /* remember current position */
    fclose(closehim->stream);
    closehim->stream = NULL;

    /* put closed file at the tail of the closed LRU list */
    Mf_unlink(closehim);
    Mf_totail(closehim,&mfc_tail);

    if (debug > 1)
	fprintf(stderr,"Mfiles: too many files open, closed file '%s'\n",
		closehim->fname);
}



static void
Mcheck(
    MFILE *pmf)
{
    /* make sure that it's open */
    if (pmf->stream == NULL) {
	if (debug > 1)
	    fprintf(stderr,"Mcheck: re-opening file '%s'\n", pmf->fname);
	Mfopen_internal(pmf,"r+");
    }

    /* put at the tail of the LRU list */
    if (mf_tail.prev != pmf) {
	Mf_unlink(pmf);
	Mf_totail(pmf,&mf_tail);
    }

}

#ifdef OLD
static void
M_printlru(void)
{
    MFILE *pmf;
    
    for (pmf = &mf_head; pmf; pmf=pmf->next)
	fprintf(stderr,"%s ==> ", pmf->fname);
    fprintf(stderr,"NULL \n");

    for (pmf = &mfc_head; pmf; pmf=pmf->next)
	fprintf(stderr,"%s ==> ", pmf->fname);
    fprintf(stderr,"NULL \n");
}
#endif /* OLD */


static void
Mf_unlink(
    MFILE *pmf)
{
    pmf->prev->next = pmf->next;
    pmf->next->prev = pmf->prev;
}


static void
Mf_totail(
    MFILE *pmf,
    MFILE *ptail)
{
    pmf->next = ptail;
    pmf->prev = ptail->prev;
    ptail->prev->next = pmf;
    ptail->prev = pmf;
}


/* try to create all of the directories in the argument */
/* like mkdirp() under Solaris, but that apparently isn't standard */
static void
M_mkdirp(char *directory)
{
    static dstring_t *pds = NULL;
    char *pch;
    char *temp;

    if (access(directory,W_OK) == 0) {
	/* it already exists */
	return;
    }

    /* make a dynamic string to store the path components */
    if (pds == NULL)
	pds = DSNew();

    if (debug)
	fprintf(stderr,"Trying to create directory '%s'\n", directory);
    

    /* walk the directory and try to create the components */
    pch = directory;
    while (pch) {
	pch = strchr(pch,'/');
	/* N.B. pch will be null on the last go around */

	/* copy that much of the directory */
	DSErase(pds);
	if (pch)
	    DSAppendStringN(pds,directory,(1 + pch - directory));
	else
	    DSAppendString(pds,directory); /* last loop */
	temp = DSVal(pds);

	/* try to create it */
	if (mkdir(temp,0755) == -1) {
	    /* this will fail with EEXIST if the directory exists,
	       which is fine */
	    if (errno != EEXIST) {
		/* couldn't make the directory */
		perror(temp);
		fprintf(stderr,
			"Unable to create directory '%s' (as part of '%s')\n",
			temp, directory);
		exit(-1);
	    }
	} else {
	    if (debug)
		fprintf(stderr,"Created directory '%s'\n", temp);
	}

	/* if pch is NULL, then we're done and will fall out,
	   else we need to increment pch past the current '/' */
	if (pch)
	    ++pch;
    }
}
