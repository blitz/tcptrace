/* 
 * name.c -- name binding stuff
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"
#include "gcache.h"


/* local routines */
static char *ServiceName(long);
static char *HostName(long);


static int verbose_debug = 0;


static char *
ServiceName(
     long port)
{
    static int cache = -1;
    tcelen len;
    struct servent *pse;
    static char port_buf[50];
    char *sb_port;

    if (nonames) {
	sprintf(port_buf,"%d",port);
	return(port_buf);
    }

    /* only small numbers have names */
    if (port > 1023) {
	sprintf(port_buf,"%d",port);
	return(port_buf);
    }


    /* check the cache */
    if (cache == -1) {
	cache = cacreate("service",250,0);
    }
    len = sizeof(port_buf);
    if (verbose_debug)
	fprintf(stderr,"Searching cache for service %d='%s'\n",
		port, port_buf);
    if (calookup(cache,
		 (char *) &port,    (tcelen) sizeof(port),
		 (char *) port_buf, &len) == OK) {
	if (verbose_debug)
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
    if (verbose_debug)
	fprintf(stderr,"Putting service %d='%s' in cache\n",
		port, sb_port);
    cainsert(cache,
	     (char *) &port,   (tcelen) sizeof(port),
	     (char *) sb_port, (tcelen) (strlen(sb_port)+1));

    return(sb_port);
}


static char *
HostName(
    long addr)
{
    tcelen len;
    static int cache = -1;
    struct in_addr ina;
    struct hostent *phe;
    char *sb_host;
    static char name_buf[100];

    ina.s_addr = addr;

    if (nonames) {
	return(inet_ntoa(ina));
    }
	
    /* check the cache */
    if (cache == -1) {
	cache = cacreate("host",250,0);
    }
    len = sizeof(name_buf);
    if (verbose_debug)
	fprintf(stderr,"Searching cache for host %x='%s'\n",
		addr, name_buf);
    if (calookup(cache,
		 (char *) &addr,    (tcelen)  sizeof(addr),
		 (char *) name_buf, &len) == OK) {
	if (verbose_debug)
	    fprintf(stderr,"Found host %x='%s' in cache\n",
		    addr, name_buf);
	return(name_buf);
    }
	

    phe = gethostbyaddr((char *)&ina, sizeof(ina), AF_INET);
    if (phe != NULL) {
	sb_host = phe->h_name;
    } else {
	sb_host = inet_ntoa(ina);
    }
    if (verbose_debug)
	fprintf(stderr,"Putting host %x='%s' in cache\n",
		addr, sb_host);
    cainsert(cache,
	     (char *) &addr,   (tcelen)sizeof(addr),
	     (char *) sb_host, (tcelen)(strlen(sb_host)+1));

    return(sb_host);
}



char *
EndpointName(
    long addr,
    long port)
{
    static char name_buf[100];
    char *sb_host;
    char *sb_port;

    sb_port = ServiceName(port);
    sb_host = HostName(addr);

    sprintf(name_buf,"%s:%s", sb_host, sb_port);

    return(name_buf);
}
