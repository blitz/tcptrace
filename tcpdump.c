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
/* Added FDDI support 9/96 Jeffrey Semke, Pittsburgh Supercomputing Center */
static char const copyright[] =
    "@(#)Copyright (c) 1996 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * tcpdump.c - TCPDUMP specific file reading stuff
 *	       For the most part, we just use the PCAP library files, which
 *	       come with tcpdump.  They are not included here.
 */


#include <stdio.h>
#include <pcap.h>
#include "tcptrace.h"


#ifdef GROK_TCPDUMP


pcap_t *pcap;


/* ugly (necessary) interaction between the pread_tcpdump() routine and */
/* the callback needed for pcap's pcap_offline_read routine		*/
static struct ether_header *callback_pep;
static struct pcap_pkthdr *callback_phdr;
static int ip_buf[MAX_IP_PACKLEN];

extern int pcap_offline_read();

/* (Courtesy Jeffrey Semke, Pittsburgh Supercomputing Center) */
/* locate ip within FDDI according to RFC 1188 */
int find_ip_fddi(char* buf, int iplen) {
      char* ptr, *ptr2;
      int i;
      char pattern[] = {0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
#define FDDIPATTERNLEN 7

      ptr = ptr2 = buf;

      for (i=0; i < FDDIPATTERNLEN; i++) {
	    ptr2 = memchr(ptr,pattern[i],(iplen - (int)(ptr - buf)));
	    if (!ptr2) 
		  return (-1);
	    if (i && (ptr2 != ptr)) {
		  ptr2 = ptr2 - i - 1;
		  i = -1;
	    }
	    ptr = ptr2 + 1;
      }
      return (ptr2 - buf + 1);
      
}

static int callback(
    char *user,
    struct pcap_pkthdr *phdr,
    char *buf)
{
    int type;
    int iplen;
    static int offset = -1;

    iplen = phdr->caplen;
    if (iplen > MAX_IP_PACKLEN)
	iplen = MAX_IP_PACKLEN;

    type = pcap_datalink(pcap);

    /* remember the stuff we always save */
    callback_phdr = phdr;
    callback_pep = (struct ether_header *) buf;
    
    /* kindof ugly, but about the only way to make them fit together :-( */
    switch (type) {
      case DLT_EN10MB:
	memcpy(ip_buf,buf+14,iplen);
	break;
      case DLT_SLIP:
	callback_pep->ether_type = htons(ETHERTYPE_IP);
	memcpy(ip_buf,buf+16,iplen);
	break;
      case DLT_FDDI:
	callback_pep->ether_type = htons(ETHERTYPE_IP);
	if (offset < 0)
	      offset = find_ip_fddi(buf,iplen);
	if (offset < 0)
	      return(-1);
	memcpy(ip_buf,buf+offset,iplen);
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
    struct ip		**ppip)
{
    int ret;

    while (1) {
	if ((ret = pcap_offline_read(pcap,1,callback,0)) != 1) {
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
	*pphys     = callback_pep;
	*pphystype = PHYS_ETHER;
	*ppip      = (struct ip *) ip_buf;
	*ptime     = callback_phdr->ts;
	*plen      = callback_phdr->len;
	*ptlen     = callback_phdr->caplen;

	/* if it's not TCP/IP, then skip it */
	if ((ntohs(callback_pep->ether_type) != ETHERTYPE_IP) ||
	    ((*ppip)->ip_p != IPPROTO_TCP)) {
	    continue;
	}

	return(1);
    }
}


int (*is_tcpdump(void))()
{
    char errbuf[100];

    if ((pcap = pcap_open_offline("-",errbuf)) == NULL) {
	if (debug > 2)
	    fprintf(stderr,"PCAP said: '%s'\n", errbuf);
	rewind(stdin);
	return(NULL);
    }

    return(pread_tcpdump);
}

#endif /* GROK_TCPDUMP */
