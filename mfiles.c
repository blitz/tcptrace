/*
 * Copyright (c) 1994, 1995, 1996
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
    "@(#)Copyright (c) 1996\nOhio University.  All rights reserved.\n";
static char const rcsid[] =
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

#include "tcptrace.h"
#include <errno.h>


struct mfile {
    FILE *stream;
    char *fname;
    MFILE *next;
    MFILE *prev;
};


/* local static routines */
static void Mcheck(MFILE *pmf);
static void Mfopen_internal(MFILE *pmf, char *mode);
static void Mf_totail(MFILE *pmf, MFILE *ptail);
static void Mf_unlink(MFILE *pmf);


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

    if (strcmp(mode,"w") != 0) {
	fprintf(stderr,"Sorry, Mfopen works only for mode \"w\"\n");
	exit(-1);
    }

    pmf = (MFILE *) MallocZ(sizeof(MFILE));

    pmf->fname = strdup(fname);
    Mfopen_internal(pmf,"w");

    /* put at the tail of the LRU list */
    Mf_totail(pmf,&mf_tail);

    return(pmf);
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

int
Mfclose(
    MFILE *pmf)
{
    Mcheck(pmf);
    return(fclose(pmf->stream));
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
    MFILE *closehim;
    
    stream = fopen(pmf->fname,mode);

    if (stream == NULL) {

	if (errno != EMFILE) {
	    perror("fopen");
	    exit(-1);
	}

	/* OK, close a file we haven't used for a while */
	closehim = mf_head.next;
	fclose(closehim->stream);
	closehim->stream = NULL;
	/* put closed file at the tail of the closed LRU list */
	Mf_unlink(closehim);
	Mf_totail(closehim,&mfc_tail);

/* 	M_printlru(); */

	if (debug > 1)
	    fprintf(stderr,"Mfiles: too many files open, closed file '%s'\n",
		    closehim->fname);

	/* now, try again */
	stream = fopen(pmf->fname,mode);
	if (stream == NULL) {
	    perror("fopen (second try)");
	    exit(-1);
	}
    }

    pmf->stream = stream;

    return;
}



static void
Mcheck(
    MFILE *pmf)
{
    /* make sure that it's open */
    if (pmf->stream == NULL) {
	if (debug > 1)
	    fprintf(stderr,"Mcheck: re-opening file '%s'\n", pmf->fname);
	Mfopen_internal(pmf,"a");
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
#endif OLD


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
