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
static char const GCC_UNUSED rcsid_gcache[] =
    "@(#)$Header$";


/* gcache.h -- a general purpose caching mechanism */


/* types used throughout */
typedef u_short	tcelen;		/* length of a cached entry		*/
typedef u_short	tceix;		/* index of a cached entry		*/
typedef u_int	thval;		/* type of the hashed value of a key	*/
typedef time_t	ttstamp;	/* type of a timestamp			*/


/* configuration constants */
#define CA_MAXENTRIES	255	/* max entries in a single cache	*/
#define CA_MAXKEY	500	/* max size of a key			*/
#define CA_MAXRES	500	/* max size of a result			*/
#define CA_NAMELEN	15	/* max length of the name of a cache	*/
#define CA_NUMCACHES	10	/* max caches in the system		*/

#define BADCID -1

#define ISBADCACHE(cid) ((cid < 0) || (cid > CA_NUMCACHES))

/* definition of the interface routines */
int cacreate(char *, int, int);
int cadestroy(int);
int cainsert(int, char *, tcelen, char *, tcelen);
int calookup(int, char *, tcelen, char *, tcelen *);
int capurge(int);
int caremove(int, char *, tcelen);
void cadump(void);
int cainit(void);



/* common defines */
#define TRUE 1
#define FALSE 0
#define OK 0     
#define SYSERR -1


