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
static char const copyright[] =
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * name.c -- name binding stuff
 * 
 * Author:	Shawn Ostermann
 * Date:	Tue Nov  1, 1994
 */

#include "tcptrace.h"
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
	sprintf(port_buf,"%hu",port);
	return(port_buf);
    }

    /* only small numbers have names */
    if (port > 1023) {
	sprintf(port_buf,"%hu",port);
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
	sprintf(port_buf,"%d",port);
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

    sprintf(name_buf,"%s:%s", sb_host, sb_port);

    return(name_buf);
}
