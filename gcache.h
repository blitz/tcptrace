/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999
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
static char const rcsid_gcache[] =
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


