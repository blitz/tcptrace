/* 
 * tcpdump.c - TCPDUMP specific file reading stuff
 *	       For the most part, we just use the PCAP library files, which
 *	       come with tcpdump.  They are not included here.
 * 
 * Author:	Shawn Ostermann
 * 		Dept. of Computer Sciences
 * 		Ohio University
 * Date:	Tue Jul 12, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#ifdef GROK_TCPDUMP

#include <stdio.h>
#include <pcap.h>
#include "tcptrace.h"


pcap_t *pcap;



static struct pcap_pkthdr hdr;
static struct ether_header ep;
static int ip_buf[IP_MAXPACKET/sizeof(int)];


static int callback(
    char *user,
    struct pcap_pkthdr *p,
    char *buf)
{
    int type;

    type = pcap_datalink(pcap);
    
    /* kindof ugly, but about the only way to make them fit together :-( */
    switch (type) {
      case DLT_EN10MB:
	memcpy(&hdr,p,sizeof(hdr));
	memcpy(&ep,buf,14);
	memcpy(ip_buf,buf+14,p->caplen);
	break;
      case DLT_SLIP:
	memcpy(&hdr,p,sizeof(hdr));
	memcpy(&ep,buf,14);
	ep.ether_type = ETHERTYPE_IP;
	memcpy(ip_buf,buf+16,p->caplen);
	break;
      default:
	fprintf(stderr,"Don't understand packet format (%d)\n", type);
	exit(1);
    }

    return(0);
};


static int
pread_tcpdump(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    struct ether_header **ppep,
    struct ip		**ppip)
{
    int ret;
    int pcap_offline_read();
    
    if ((ret = pcap_offline_read(pcap,1,callback,0)) != 1) {
	/* prob EOF */
	return(0);
    }

    /* fill in all of the return values */
    *ptime = hdr.ts;
    *plen  = hdr.len;
    *ptlen = hdr.caplen;
    *ppip  = (struct ip *) ip_buf;
    *ppep  = &ep;

    return(1);
}


int (*is_tcpdump())()
{
    char errbuf[100];

    if ((pcap = pcap_open_offline("-",errbuf)) == NULL) {
	fprintf(stderr,"PCAP said: '%s'\n", errbuf);
	rewind(stdin);
	return(NULL);
    }

    return(pread_tcpdump);
}

#endif GROK_TCPDUMP
