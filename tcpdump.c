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



/* ugly (necessary) interaction between the pread_tcpdump() routine and */
/* the callback needed for pcap's pcap_offline_read routine		*/
static struct ether_header *callback_pep;
static struct pcap_pkthdr *callback_phdr;
static int ip_buf[MAX_IP_PACKLEN];



static int callback(
    char *user,
    struct pcap_pkthdr *phdr,
    char *buf)
{
    int type;
    int iplen;

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
	callback_pep->ether_type = ETHERTYPE_IP;
	memcpy(ip_buf,buf+16,iplen);
	break;
      default:
	fprintf(stderr,"Don't understand packet format (%d)\n", type);
	exit(1);
    }

    return(0);
};


/* currently only works for ETHERNET */
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
    int pcap_offline_read();

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
	if ((callback_pep->ether_type != ETHERTYPE_IP) ||
	    ((*ppip)->ip_p != IPPROTO_TCP)) {
	    continue;
	}

	return(1);
    }
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
