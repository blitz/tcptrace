/*
 * Copyright (c) 1994, 1995, 1996, 1997
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

#include <stdio.h>
#include "tcptrace.h"

#ifdef GROK_TCPDUMP

#include "tcpdump.h"
#include <pcap.h>




/* external ref, in case missing in older version */
extern int pcap_offline_read(void *, int, pcap_handler, u_char *);

/* global pointer, the pcap info header */
static pcap_t *pcap;


/* Interaction with pcap */
static struct ether_header eth_header;
#define EH_SIZE sizeof(struct ether_header)
static int ip_buf[IP_MAXPACKET/sizeof(int)];
static struct pcap_pkthdr *callback_phdr;
static void *callback_plast;


static int callback(
    char *user,
    struct pcap_pkthdr *phdr,
    char *buf)
{
    int type;
    int iplen;
    static int offset = -1;

    iplen = phdr->caplen;
    if (iplen > IP_MAXPACKET)
	iplen = IP_MAXPACKET;

    type = pcap_datalink(pcap);

    /* remember the stuff we always save */
    callback_phdr = phdr;

    /* kindof ugly, but about the only way to make them fit together :-( */
    switch (type) {
      case DLT_EN10MB:
	memcpy(&eth_header,buf,EH_SIZE);  /* save ether header */
	memcpy(ip_buf,buf+EH_SIZE,iplen);
	callback_plast = (char *)ip_buf+iplen-EH_SIZE-1;
	break;
      case DLT_SLIP:
	memcpy(ip_buf,buf+16,iplen);
	callback_plast = (char *)ip_buf+iplen-16-1;
	break;
      case DLT_FDDI:
	if (offset < 0)
	      offset = find_ip_fddi(buf,iplen);
	if (offset < 0)
	      return(-1);
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      case DLT_NULL:
	/* no phys header attached */
	offset = 4;
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      default:
	fprintf(stderr,"Don't understand packet format (%d)\n", type);
	exit(1);
    }

    return(0);
}


/* currently only works for ETHERNET and FDDI */
static int
pread_tcpdump(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int ret;

    while (1) {
	if ((ret = pcap_offline_read(pcap,1,(pcap_handler)callback,0)) != 1) {
	    /* prob EOF */

	    if (ret == -1) {
		char *error;
		error = pcap_geterr(pcap);

		if (error && *error)
		    fprintf(stderr,"PCAP error: '%s'\n",pcap_geterr(pcap));
		/* else, it's just EOF */
	    }
	    
	    return(0);
	}

	/* fill in all of the return values */
	*pphys     = &eth_header;/* everything assumed to be ethernet */
	*pphystype = PHYS_ETHER; /* everything assumed to be ethernet */
	*ppip      = (struct ip *) ip_buf;
	*pplast    = callback_plast; /* last byte in IP packet */
	*ptime     = callback_phdr->ts;
	*plen      = callback_phdr->len;
	*ptlen     = callback_phdr->caplen;

	/* if it's not IP, then skip it */
	if ((ntohs(eth_header.ether_type) != ETHERTYPE_IP) &&
	    (ntohs(eth_header.ether_type) != ETHERTYPE_IPV6)) {
	    if (debug > 2)
		fprintf(stderr,"pread_tcpdump: not an IP packet\n");
	    continue;
	}

	return(1);
    }
}


pread_f *is_tcpdump(void)
{
    char errbuf[100];
    char *physname = "<unknown>";
    int type;

    if ((pcap = pcap_open_offline("-",errbuf)) == NULL) {
	if (debug > 2)
	    fprintf(stderr,"PCAP said: '%s'\n", errbuf);
	rewind(stdin);
	return(NULL);
    }


    if (debug)
	printf("Using 'pcap' version of tcpdump\n");

    /* check the phys type (pretend everything is ethernet) */
    memset(&eth_header,0,EH_SIZE);
    switch (type = pcap_datalink(pcap)) {
      case DLT_EN10MB:
	/* OK, we understand this one */
	physname = "Ethernet";
	break;
      case DLT_SLIP:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "Slip";
	break;
      case DLT_FDDI:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "FDDI";
	break;
      case DLT_NULL:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "NULL";
	break;
      default:
	if (debug)
	    fprintf(stderr,"is_tcpdump: Don't understand packet format (%d)\n", type);
	rewind(stdin);
	return(NULL);
    }

    if (debug)
	fprintf(stderr,"Tcpdump format, physical type is %d (%s)\n",
		type, physname);


    return(pread_tcpdump);
}


#endif /* GROK_TCPDUMP */
