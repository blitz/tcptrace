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
static char const GCC_UNUSED rcsid_file_formats[] =
    "@(#)$Header$";


/* 
 * file_formats.h -- Which file formats are supported
 */



/**************************************************************/
/**                                                          **/
/**  Input File Specific Stuff                               **/
/**                                                          **/
/**************************************************************/

struct supported_formats {
    pread_f	*(*test_func)(char *filename);	/* pointer to the tester function	*/
    char	*format_name;	/* name of the file format		*/
    char	*format_descr;	/* description of the file format	*/
};

/* for each file type GLORP you want to support, provide a      	*/
/* function is_GLORP() that returns NULL if the stdin file is NOT	*/
/* of type GLORP, and returns a pointer to a packet reading routine	*/
/* if it is.  The packet reading routine is of the following type:	*/
/*	int pread_GLORP(						*/
/*	    struct timeval	*ptime,					*/
/*	    int		 	*plen,					*/
/*	    int		 	*ptlen,					*/
/*	    void		**pphys,				*/
/*	    int			*pphystype,				*/
/*	    struct ip		**ppip,					*/
/*	    void		**pplast)				*/
/*   the reader function should return 0 at EOF and 1 otherwise		*/
/* This routine must return ONLY IP packets, but they need not all be	*/
/* TCP packets (if not, they're ignored).				*/


/* install the is_GLORP() routines supported */
struct supported_formats file_formats[] = {
#ifdef GROK_TCPDUMP
	{is_tcpdump,	"tcpdump","tcpdump -- Public domain program from LBL"},
#endif /* GROK_TCPDUMP */
#ifdef GROK_SNOOP
	{is_snoop,	"snoop","Sun Snoop -- Distributed with Solaris"},
#endif /* GROK_SNOOP */
#ifdef GROK_ETHERPEEK
	{is_EP,		"etherpeek","etherpeek -- Mac sniffer program"},
#endif /* GROK_ETHERPEEK */
#ifdef GROK_NETM
	{is_netm,	"netmetrix","Net Metrix -- Commercial program from HP"},
#endif /* GROK_NETM */
#ifdef GROK_NS
	{is_ns,		"ns","ns -- network simulator from LBL"},
#endif /* GROK_NS */
#ifdef GROK_NLANR
	{is_nlanr,	"tsh","NLANL Tsh Format"},
#endif /* GROK_NLANR */
#ifdef GROK_NETSCOUT
	{is_netscout,	"netscout","NetScout Manager format"},
#endif /* GROK_NETSCOUT */
#ifdef GROK_ERF
	{is_erf,	"erf","Endace Extensible Record Format"},
#endif /* GROK_ERF */
};

#define NUM_FILE_FORMATS (sizeof(file_formats) / sizeof(struct supported_formats))
