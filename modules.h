/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
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
    /* is this module being called? */
    Bool	module_inuse;

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
	struct ip *pip,		/* the packet */
	tcp_pair *ptp,		/* info I have about this connection */
	void *plast,		/* pointer to last byte */
	void *pmodstruct);	/* module-specific structure */

    /* Finish up routine.  Called after tcpdump is finished printing.	*/
    void (*module_done) (void);

    /* Usage message additions */
    void (*module_usage)(void);

    /* If you want to be called as each file is processed */
    void (*module_newfile)(
	char *filename,		/* the name of the current file */
	u_long filesize,	/* number of bytes in file (might be compressed) */
	Bool fcompressed);	/* is the file compressed? */

    /* If you want to be called for each new connection */
    /* If you want to attach a module-specifi structure to this */
    /* tcp_pair, return its address and I'll hand it back to */
    /* you with each read, otherwise return NULL  */
    void *(*module_newconn)(
	tcp_pair *ptp);		/* info I have about this connection */
};


/* module-specific header file (needs to give prototypes for the routines below) */
#ifdef LOAD_MODULE_HTTP
#include "mod_http.h"		/* for the HTTP package */
#endif /* LOAD_MODULE_HTTP */


#ifdef LOAD_MODULE_TRAFFIC
#include "mod_traffic.h"	/* for the traffic package */
#endif /* LOAD_MODULE_TRAFFIC */


#ifdef LOAD_MODULE_RTTGRAPH
#include "mod_rttgraph.h"	/* for the rttgraph package */
#endif /* LOAD_MODULE_RTTGRAPH */

#ifdef LOAD_MODULE_COLLIE
#include "mod_collie.h"	/* for the collie package */
#endif /* LOAD_MODULE_COLLIE */


/* declare (install) the various module routines */
struct module modules[] = {
#ifdef LOAD_MODULE_HTTP
    /* this example is for the HTTP module */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "http",			/* name of the module */
     "Http analysis package",	/* description of the module */
     http_init,			/* routine to call to init the module */
     http_read,			/* routine to pass each TCP segment */
     http_done,			/* routine to call at program end */
     http_usage,		/* routine to call to print module usage */
     http_newfile,		/* routine to call on each new file */
     http_newconn},		/* routine to call on each new connection */
#endif /* LOAD_MODULE_HTTP */

    /* list other modules here ... */

#ifdef LOAD_MODULE_TRAFFIC
    /* ttl traffic analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "traffic", "traffic analysis package",
     traffic_init, traffic_read, traffic_done,		
     traffic_usage, NULL, traffic_newconn},
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_RTTGRAPH
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "rttgraph", "round trip time analysis graphs",
     rttgraph_init,		/* routine to call to init the module */
     rttgraph_read,		/* routine to pass each TCP segment */
     rttgraph_done,		/* routine to call at program end */
     rttgraph_usage,		/* routine to call to print module usage */
     NULL,			/* routine to call on each new file */
     rttgraph_newconn},		/* routine to call on each new connection */
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_COLLIE
    /* ttl collie analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "collie", "connection summary package",
     collie_init, NULL /* read */, collie_done,		
     collie_usage, NULL, collie_newconn},
#endif /* LOAD_MODULE_COLLIE */
};
#define NUM_MODULES (sizeof(modules) / sizeof(struct module))
