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


/* 
 * file_formats.h -- Which file formats are supported
 */



/**************************************************************/
/**                                                          **/
/**  Input File Specific Stuff                               **/
/**                                                          **/
/**************************************************************/

struct supported_formats {
    int	(*(*test_func)())(void);/* pointer to the tester function	*/
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
/*	    struct ip		**ppip)					*/
/*   the reader function should return 0 at EOF and 1 otherwise		*/
/* This routine must return ONLY IP packets, but they need not all be	*/
/* TCP packets (if not, they're ignored).				*/


/* give the prototypes for the is_GLORP() routines supported */
#ifdef GROK_SNOOP
	int (*is_snoop(void))();
#endif GROK_SNOOP
#ifdef GROK_NETM
	int (*is_netm(void))();
#endif GROK_NETM
#ifdef GROK_TCPDUMP
	int (*is_tcpdump(void))();
#endif GROK_TCPDUMP
#ifdef GROK_ETHERPEEK
	int (*is_EP(void))();
#endif GROK_ETHERPEEK


/* install the is_GLORP() routines supported */
struct supported_formats file_formats[] = {
#ifdef GROK_TCPDUMP
	{is_tcpdump,	"tcpdump","tcpdump -- Public domain program from LBL"},
#endif GROK_TCPDUMP
#ifdef GROK_SNOOP
	{is_snoop,	"snoop","Sun Snoop -- Distributed with Solaris"},
#endif GROK_SNOOP
#ifdef GROK_ETHERPEEK
	{is_EP,		"etherpeek", "etherpeek -- Mac sniffer program"},
#endif GROK_ETHERPEEK
#ifdef GROK_NETM
	{is_netm,	"netmetrix","Net Metrix -- Commercial program from HP"},
#endif GROK_NETM
	{NULL,NULL},	/* You must NOT remove this entry */
};
