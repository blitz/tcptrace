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
static char const GCC_UNUSED rcsid_modules[] =
    "$Header$";


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

    /* TCP Reading routine, for each packet grabbed, I'll pass you the	*/
    /* TCP structure and the IP packet itself (in			*/
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

    /* UDP Reading routine, for each packet grabbed, I'll pass you the	*/
    /* UDP structure and the IP packet itself (in			*/
    /* host byte order).						*/
    void (*module_udp_read) (
	struct ip *pip,		/* the packet */
	udp_pair *pup,		/* info I have about this connection */
	void *plast,		/* pointer to last byte */
	void *pmodstruct);	/* module-specific structure */

    /* If you want to be called for each new UDP connection */
    /* If you want to attach a module-specifi structure to this */
    /* udp_pair, return its address and I'll hand it back to */
    /* you with each read, otherwise return NULL  */
    void *(*module_udp_newconn)(
	udp_pair *ptp);		/* info I have about this connection */

    /* Called for non-tcp packets.  Tcptrace ignores them, but you */
    /* might want them */
    void (*module_nontcpudp_read) (
	struct ip *pip,		/* the packet */
	void *plast);		/* pointer to last byte */

    /* Called for old TCP connections when they are deleted by */
    /* the real-time version of the program */ 
    void (*module_deleteconn) (
	 tcp_pair *ptp,		/* info I have about this connection */
	 void *pmodstruct);	/* module-specific structure */
};


/* module-specific header file (needs to give prototypes for the routines below) */
#ifdef LOAD_MODULE_HTTP
#include "mod_http.h"		/* for the HTTP package */
#endif /* LOAD_MODULE_HTTP */


#ifdef LOAD_MODULE_TCPLIB
#include "mod_tcplib.h"		/* for the TCPLIB package */
#endif /* LOAD_MODULE_TCPLIB */


#ifdef LOAD_MODULE_TRAFFIC
#include "mod_traffic.h"	/* for the traffic package */
#endif /* LOAD_MODULE_TRAFFIC */


#ifdef LOAD_MODULE_RTTGRAPH
#include "mod_rttgraph.h"	/* for the rttgraph package */
#endif /* LOAD_MODULE_RTTGRAPH */

#ifdef LOAD_MODULE_COLLIE
#include "mod_collie.h"	/* for the collie package */
#endif /* LOAD_MODULE_COLLIE */


#ifdef LOAD_MODULE_SLICE
#include "mod_slice.h"	/* for the slice package */
#endif /* LOAD_MODULE_SLICE */


#ifdef LOAD_MODULE_REALTIME
#include "mod_realtime.h"       /* for the example real-time package */
#endif /* LOAD_MODULE_REALTIME */

#ifdef LOAD_MODULE_INBOUNDS
#include "mod_inbounds.h"       /* include the INBOUNDS module */
#endif /* LOAD_MODULE_INBOUNDS */

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
     http_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_HTTP */

    /* list other modules here ... */
#ifdef LOAD_MODULE_TCPLIB
    /* this example is for the TCPLIB module */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "tcplib",			/* name of the module */
     "TCPLib analysis package",	/* description of the module */
     tcplib_init,		/* routine to call to init the module */
     tcplib_read,		/* routine to pass each TCP segment */
     tcplib_done,		/* routine to call at program end */
     tcplib_usage,		/* routine to call to print module usage */
     tcplib_newfile,		/* routine to call on each new file */
     tcplib_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_TCPLIB */


#ifdef LOAD_MODULE_TRAFFIC
    /* ttl traffic analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "traffic", "traffic analysis package",
     traffic_init, traffic_read, traffic_done,		
     traffic_usage, NULL, traffic_newconn, NULL, NULL, NULL, NULL},
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_SLICE
    /* ttl slice analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "slice", "traffic efficiency data by time slices",
     slice_init, slice_read, slice_done,		
     slice_usage, NULL, slice_newconn, NULL, NULL, NULL, NULL},
#endif /* LOAD_MODULE_SLICE */

#ifdef LOAD_MODULE_RTTGRAPH
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "rttgraph", "round trip time analysis graphs",
     rttgraph_init,		/* routine to call to init the module */
     rttgraph_read,		/* routine to pass each TCP segment */
     rttgraph_done,		/* routine to call at program end */
     rttgraph_usage,		/* routine to call to print module usage */
     NULL,			/* routine to call on each new file */
     rttgraph_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_COLLIE
    /* ttl collie analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "collie", "connection summary package",
     collie_init, NULL /* read */, collie_done,		
     collie_usage, collie_newfile, collie_newconn,
     NULL, collie_newudpconn, NULL, NULL},
#endif /* LOAD_MODULE_COLLIE */

#ifdef LOAD_MODULE_REALTIME
    {TRUE,		         /* make FALSE if you don't want to call it at all */
     "realtime",                 /* name of the module */
     "example real-time package",/* description of the module */
     realtime_init,		 /* routine to call to init the module */
     realtime_read,		 /* routine to pass each TCP segment */
     realtime_done,		 /* routine to call at program end */
     realtime_usage,		 /* routine to call to print module usage */
     NULL,			 /* routine to call on each new file */
     realtime_newconn,		 /* routine to call on each new connection */
     realtime_udp_read,          /* routine to pass each UDP segment */
     NULL,              	 /* routine to call on each new UDP conn */
     realtime_nontcpudp_read, 	 /* routine to pass each non-tcp and non-udp 
				    packets*/
     realtime_deleteconn},
#endif /* LOAD_MODULE_REALTIME */
  
#ifdef LOAD_MODULE_INBOUNDS
    {TRUE,		         /* make FALSE if you don't want to call it at all */
     "inbounds",                 /* name of the module */
     "INBOUNDS analysis package",/* description of the module */
     inbounds_init,		 /* routine to call to init the module */
     inbounds_tcp_read,		 /* routine to pass each TCP segment */
     inbounds_done,		 /* routine to call at program end */
     inbounds_usage,		 /* routine to call to print module usage */
     NULL,			 /* routine to call on each new file */
     inbounds_tcp_newconn,		 /* routine to call on each new connection */
     inbounds_udp_read,          /* routine to pass each UDP segment */
     inbounds_udp_newconn,       /* routine to call on each new UDP conn */
     inbounds_nontcpudp_read, 	 /* routine to pass each non-tcp and non-udp 
				    packets*/
     inbounds_tcp_deleteconn},        /* routine to remove TCP connections */
#endif /* LOAD_MODULE_INBOUNDS */
  
};
#define NUM_MODULES (sizeof(modules) / sizeof(struct module))
