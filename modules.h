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
static char const rcsid_modules[] =
    "$Id$";


/* 
 * modules.h -- Definitions for plug-in modules
 */


/* For a registered module, enter its info into the following structures */

struct module {
    /* The SHORT name of the module, just for debugging */
    char	*module_name;

    /* The LONG description of the module, just for debugging */
    char	*module_descr;

    /* Init routine, called immediately at start-up time 		*/
    /* I'll pass you the argc and argv from the program invocation, 	*/
    /* delete any args you want (just make the pointer NULL)		*/
    /* If you return TRUE, I'll call the other functions later, else	*/
    /* I won't.								*/
    int (*module_init) (int argc, char *argv[]);

    /* Reading routing, for each packet grabbed, I'll pass you the TCP	*/
    /* structure and the IP packet itself (in				*/
    /* host byte order).						*/
    void (*module_read) (
	struct ip *pip,	/* the packet */
	tcp_pair *ptp,	/* info I have about this connection */
	void *plast);	/* pointer to last byte */

    /* Finish up routine.  Called after tcpdump is finished printing.	*/
    void (*module_done) (void);

    /* Usage message additions */
    void (*module_usage)();
};


#include "mod_http.h"	/* for the HTTP package */

/* install the is_GLORP() routines supported */
struct module modules[] = {
	{"http", "Http measurement package",
	 http_init, http_read, http_done, http_usage},
	{NULL,NULL},	/* You must NOT remove this entry */
};
