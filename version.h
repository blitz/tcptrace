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
static char const rcsid_version[] =
    "@(#)$Header$";


/* source code version information */
#define VERSION_MAJOR	"6"
#define VERSION_MINOR	"0"
#define VERSION_BUGFIX	"1a1"
#define VERSION_DATE	"Tue May  8, 2001"

#define VERSION_NUM   VERSION_MAJOR "." VERSION_MINOR "." VERSION_BUGFIX

/* the string to print */
#define VERSION  "Ostermann's tcptrace -- version " VERSION_NUM " -- " VERSION_DATE


/* build information */
/* constants filled in when version.c is compiled */
extern char *built_bywhom;
extern char *built_when;
extern char *built_where;
