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
static char const GCC_UNUSED rcsid_dstring[] =
    "@(#)$Header$";



/* our dynamic string structure */
struct dstring {
    char *buf;
    int ix_nextch;
    int buflen;
};


/* local routines */
static void DSExpand(struct dstring *pds);

/* make the total string size longer */
static void
DSExpand(struct dstring *pds)
{
    unsigned newsize;
    char *newbuf;
    
    /* choose a new size */
    if (pds->buflen == 0)
	newsize = 64;
    else if (pds->buflen < (16*1024))
	newsize = pds->buflen * 2;
    else
	newsize = pds->buflen +(4*1024);

    /* make the new buffer (using the old one if possible) */
    newbuf = ReallocZ(pds->buf,pds->buflen,newsize);

    pds->buflen = newsize;
    pds->buf = newbuf;
}






/* Make a new dstring */
struct dstring *
DSNew(void)
{
    struct dstring *pret;

    /* malloc and zero out */
    pret = MallocZ(sizeof(struct dstring));

    return(pret);
}



/* Destroy a dstring */
void
DSDestroy(struct dstring **ppds)
{
    free((*ppds)->buf);
    free((*ppds));
    *ppds = NULL;
}




/* erase the string, but leave the structure otherwise intact */
void
DSErase(
    struct dstring *pds)
{
    pds->ix_nextch = 0;
}



/* append a character to a dstring */
void
DSAppendChar(
    struct dstring *pds,
    char ch)
{
    /* status:
       buf[0,1,2,...(buflen-1)] are valid
       buf[ix_nextch] is where the next character should go
       if (ix_nextch > (buflen-1)), then it's full
       same as (ix_nextch+1 > (buflen))
    */
    if (1 /* for the null */ + pds->ix_nextch+1 > pds->buflen) {
	DSExpand(pds);
    }

    pds->buf[pds->ix_nextch++] = ch;
    pds->buf[pds->ix_nextch] = '\00'; /* keep it NULL terminated */
}



/* append a normal string to the end of a dstring */
void
DSAppendString(
    struct dstring *pds,
    char *str)
{
    while (*str) {
	DSAppendChar(pds,*str);
	++str;
    }
}


/* append at most 'len' characters from a normal string to a dstring */
void
DSAppendStringN(
    struct dstring *pds,
    char *str,
    int len)
{
    while (*str) {
	if (len-- <= 0)
	    break;
	DSAppendChar(pds,*str);
	++str;
    }
}


/* return the value of the string */
char *
DSVal(
    struct dstring *pds)
{
    if (pds->buflen)
	return(pds->buf);
    else
	return("");		/* not used yet, treat as null */
}
