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
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";


/* 
 * name.c -- name binding stuff
 * 
 * Author:	Shawn Ostermann
 * Date:	Tue Nov  1, 1994
 */

#include "gcache.h"


/* local routines */


char *
ServiceName(
     portnum port)
{
    static int cache = -1;
    tcelen len;
    struct servent *pse;
    static char port_buf[20];
    char *sb_port;

    if (!resolve_ports) {
	snprintf(port_buf,sizeof(port_buf),"%hu",port);
	return(port_buf);
    }

    /* only small numbers have names */
    if (port > 1023) {
	snprintf(port_buf,sizeof(port_buf),"%hu",port);
	return(port_buf);
    }


    /* check the cache */
    if (cache == -1) {
	cache = cacreate("service",250,0);
    }
    len = sizeof(port_buf);
    if (debug > 2)
	fprintf(stderr,"Searching cache for service %d='%s'\n",
		port, port_buf);
    if (calookup(cache,
		 (char *) &port,    (tcelen) sizeof(port),
		 (char *) port_buf, &len) == OK) {
	if (debug > 2)
	    fprintf(stderr,"Found service %d='%s' in cache\n",
		    port, port_buf);
	return(port_buf);
    }
	

    /* get port name as a string */
    pse = getservbyport(port,"tcp");
    if (pse != NULL) {
	sb_port = pse->s_name;
    } else {
	snprintf(port_buf,sizeof(port_buf),"%d",port);
	sb_port = port_buf;
    }
    if (debug > 2)
	fprintf(stderr,"Putting service %d='%s' in cache\n",
		port, sb_port);
    cainsert(cache,
	     (char *) &port,   (tcelen) sizeof(port),
	     (char *) sb_port, (tcelen) (strlen(sb_port)+1));

    return(sb_port);
}


/* turn an ipaddr into a printable format */
/* N.B. - result comes from static memory, save it before calling back! */
char *
HostAddr(
    ipaddr ipaddress)
{
    char *adr;

    if (ADDR_ISV6(&ipaddress)) {
	static char adrv6[INET6_ADDRSTRLEN];
	my_inet_ntop(AF_INET6,(char *) ipaddress.un.ip6.s6_addr,
		     adrv6, INET6_ADDRSTRLEN);
	adr = adrv6;
    } else {
	adr = inet_ntoa(ipaddress.un.ip4);
    }
        
    return(adr);
}



char *
HostName(
    ipaddr ipaddress)
{
    tcelen len;
    static int cache = -1;
    struct hostent *phe;
    char *sb_host;
    static char name_buf[100];
    char *adr;

    adr = HostAddr(ipaddress);

    if (!resolve_ipaddresses) {
	return(adr);
    }
	
    /* check the cache */
    if (cache == -1) {
	cache = cacreate("host",250,0);
    }
    len = sizeof(name_buf);
    if (debug > 2)
	fprintf(stderr,"Searching cache for host '%s'\n",
		adr);
    if (calookup(cache,
		 (char *) &ipaddress,    (tcelen)  sizeof(ipaddress),
		 (char *) name_buf, &len) == OK) {
	if (debug > 2)
	    fprintf(stderr,"Found host %s='%s' in cache\n",
		    adr, name_buf);
	return(name_buf);
    }
	

    if (ADDR_ISV6(&ipaddress))
	phe = gethostbyaddr ((char *)&ipaddress.un.ip6,
			     sizeof(ipaddress.un.ip6), AF_INET6);
    else
	phe = gethostbyaddr((char *)&ipaddress.un.ip4,
			    sizeof(ipaddress.un.ip4), AF_INET);
    if (phe != NULL) {
	sb_host = phe->h_name;
    } else {
	sb_host = adr;
    }

    if (use_short_names) {
	char *pdot;

	if ((pdot = strchr(sb_host,'.')) != NULL) {
	    *pdot = '\00';  /* chop off the end */
	}
    }

    if (debug > 2)
	fprintf(stderr,"Putting host %s='%s' in cache\n",
		adr, sb_host);

    cainsert(cache,
	     (char *) &ipaddress,   (tcelen)sizeof(ipaddress),
	     (char *) sb_host, (tcelen)(strlen(sb_host)+1));

    return(sb_host);
}



char *
EndpointName(
    ipaddr ipaddress,
    portnum port)
{
    static char name_buf[100];
    char *sb_host;
    char *sb_port;

    sb_host = HostName(ipaddress);
    sb_port = ServiceName(port);

    snprintf(name_buf,sizeof(name_buf),"%s:%s", sb_host, sb_port);

    return(name_buf);
}
