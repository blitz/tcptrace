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
static char const rcsid_compress[] =
    "$Header$";

#define COMP_HDR_SIZE (8*1024)	/* number of bytes from a compressed file that */
				/* we save into a real file for header check, */
				/* the rest we read from a pipe (if long) */


/* How to identify various comp formats */
#define COMP_MAX_ARGS 20	/* maximum args that you can specify */
struct comp_formats {
    char	*comp_suffix;	/* how to recognize these files		*/
    char	*comp_descr;	/* description of the file format	*/
    char	*comp_bin;	/* name of the binary (full path preferred) */
    char	*comp_args[COMP_MAX_ARGS]; /* arguments to pass */
};

/*
 * compression format table:
 * Don't forget:!!!
 *  1) Leave the last line of NULLs alone
 *  2) arg 1 MUST be the name of the program
 *  3) last arg MUST be NULL
 *  4) only the first suffix match is used
 *  5) an arg of "%s" will be replaced with the file name,
 *     don't forget to include it!
 *  6) don't forget the "dot" in the suffix (if there is one)
 */

struct comp_formats supported_comp_formats[] = {
/*   SUFFIX    DESCRIPTION	    BINARY NAME	   ARGS TO EXECV	*/
/*   -----   --------------------   -----------   ----------------------*/
#ifdef GUNZIP
    {".gz", "Gnu gzip format",	    GUNZIP,     {"gunzip","-c","%s",NULL}},
    {".Z",  "Unix compress format", GUNZIP,     {"gunzip","-c","%s",NULL}},
#endif /* GUNZIP */

#ifdef UNCOMPRESS
    {".Z",  "Unix compress format", UNCOMPRESS, {"uncompress","-c","%s",NULL}},
#endif /* UNCOMPRESS */

#ifdef BUNZIP2
    {".bz2", "bzip2 format", BUNZIP2, {"bunzip2","-c","%s",NULL}},
#endif /* BUNZIP2 */
};
#define NUM_COMP_FORMATS (sizeof(supported_comp_formats) / sizeof(struct comp_formats))

