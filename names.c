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


char *
ServiceName(
     portnum port)
{
    static int cache = -1;
    tcelen len;
    struct servent *pse;
    static char port_buf[20];
    char *sb_port;

    if (nonames) {
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


char *
HostName(
    ipaddr ipaddress)
{
    tcelen len;
    static int cache = -1;
    struct hostent *phe;
    char *sb_host;
    static char name_buf[100];

    if (nonames) {
	return(inet_ntoa(ipaddress));
    }
	
    /* check the cache */
    if (cache == -1) {
	cache = cacreate("host",250,0);
    }
    len = sizeof(name_buf);
    if (debug > 2)
	fprintf(stderr,"Searching cache for host '%s'\n",
		inet_ntoa(ipaddress));
    if (calookup(cache,
		 (char *) &ipaddress,    (tcelen)  sizeof(ipaddress),
		 (char *) name_buf, &len) == OK) {
	if (debug > 2)
	    fprintf(stderr,"Found host %s='%s' in cache\n",
		    inet_ntoa(ipaddress), name_buf);
	return(name_buf);
    }
	

    phe = gethostbyaddr((char *)&ipaddress, sizeof(ipaddress), AF_INET);
    if (phe != NULL) {
	sb_host = phe->h_name;
    } else {
	sb_host = inet_ntoa(ipaddress);
    }

    if (use_short_names) {
	char *pdot;

	if ((pdot = strchr(sb_host,'.')) != NULL) {
	    *pdot = '\00';  /* chop off the end */
	}
    }

    if (debug > 2)
	fprintf(stderr,"Putting host %s='%s' in cache\n",
		inet_ntoa(ipaddress), sb_host);
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
