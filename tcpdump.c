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
static int *ip_buf;  /* [IP_MAXPACKET/sizeof(int)] */
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
      case 100:
	/* for some reason, the windows version of tcpdump is using */
	/* this.  It looks just like ethernet to me */
      case DLT_EN10MB:
	memcpy(&eth_header,buf,EH_SIZE);  /* save ether header */
	memcpy(ip_buf,buf+EH_SIZE,iplen);
	callback_plast = (char *)ip_buf+iplen-EH_SIZE-1;
	break;
      case DLT_IEEE802:
	/* just pretend it's "normal" ethernet */
	offset = 14;		/* 22 bytes of IEEE cruft */
	memcpy(&eth_header,buf,EH_SIZE);  /* save ether header */
	memcpy(ip_buf,buf+offset,iplen);
	callback_plast = (char *)ip_buf+iplen-offset-1;
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
      case DLT_ATM_RFC1483:
	/* ATM RFC1483 - LLC/SNAP ecapsulated atm */
	memcpy((char *)ip_buf,buf+8,iplen);
	callback_plast = ip_buf+iplen-8-1;
	break;
      case DLT_RAW:
	/* raw IP */
	offset = 0;
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      default:
	fprintf(stderr,"Don't understand link-level format (%d)\n", type);
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

	/* at least one tcpdump implementation (AIX) seems to be */
	/* storing NANOseconds in the usecs field of the timestamp. */
	/* This confuses EVERYTHING.  Try to compensate. */
	{
	    static Bool bogus_nanoseconds = FALSE;
	    if ((callback_phdr->ts.tv_usec >= US_PER_SEC) ||
		(bogus_nanoseconds)) {
		if (!bogus_nanoseconds) {
		    fprintf(stderr,
			    "tcpdump: attempting to adapt to bogus nanosecond timestamps\n");
		    bogus_nanoseconds = TRUE;
		}
		callback_phdr->ts.tv_usec /= 1000;
	    }
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


    if (debug) {
	printf("Using 'pcap' version of tcpdump\n");
	if (debug > 1) {
	    printf("\tversion_major: %d\n", pcap_major_version(pcap));
	    printf("\tversion_minor: %d\n", pcap_minor_version(pcap));
	    printf("\tsnaplen: %d\n", pcap_snapshot(pcap));
	    printf("\tlinktype: %d\n", pcap_datalink(pcap));
	    printf("\tswapped: %d\n", pcap_is_swapped(pcap));
	}
    }

    /* check the phys type (pretend everything is ethernet) */
    memset(&eth_header,0,EH_SIZE);
    switch (type = pcap_datalink(pcap)) {
case 100:
      case DLT_EN10MB:
	/* OK, we understand this one */
	physname = "Ethernet";
	break;
      case DLT_IEEE802:
	/* just pretend it's normal ethernet */
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
      case DLT_ATM_RFC1483:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "ATM, LLC/SNAP encapsulated";
	break;
      case DLT_RAW:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "RAW_IP";
	break;
      default:
	if (debug)
	    fprintf(stderr,"is_tcpdump: I think it's tcpdump, but I don't understand link format (%d)\n", type);
	rewind(stdin);
	return(NULL);
    }

    if (debug)
	fprintf(stderr,"Tcpdump format, physical type is %d (%s)\n",
		type, physname);

    /* set up some stuff */
    ip_buf = MallocZ(IP_MAXPACKET);


    return(pread_tcpdump);
}


/* support for writing a new pcap file */

void
PcapSavePacket(
    char *filename,
    struct ip *pip,
    void *plast)
{
    static FILE *f_savefile = NULL;
    struct pcap_pkthdr phdr;
    int wlen;

    if (f_savefile == NULL) {
	struct pcap_file_header fhdr;

	/* try to open the file */
	if ((f_savefile = fopen(filename, "w")) == NULL) {
	    perror(filename);
	    exit(-1);
	}
	
	/* make up the header info it wants */
	/* this comes from version 2.4, no pcap routine handy :-(  */
	fhdr.magic = TCPDUMP_MAGIC;
	fhdr.version_major = PCAP_VERSION_MAJOR;
	fhdr.version_minor = PCAP_VERSION_MINOR;

	fhdr.thiszone = 0;	/* don't have this info, just make it up */
	fhdr.snaplen = 1000000;	/* don't have this info, just make it up */
	fhdr.linktype = DLT_EN10MB; /* always Ethernet (10Mb) */
	fhdr.sigfigs = 0;

	/* write the header */
	fwrite((char *)&fhdr, sizeof(fhdr), 1, f_savefile);

	if (debug)
	    fprintf(stderr,"Created pcap save file '%s'\n", filename);
    }

    /* create the packet header */
    phdr.ts = current_time;
    phdr.caplen = (unsigned)plast - (unsigned)pip + 1;
    phdr.caplen += EH_SIZE;	/* add in the ether header */
    phdr.len = EH_SIZE + ntohs(PIP_LEN(pip));	/* probably this */

    /* write the packet header */
    fwrite(&phdr, sizeof(phdr), 1, f_savefile);

    /* write a (bogus) ethernet header */
    memset(&eth_header,0,EH_SIZE);
    eth_header.ether_type = htons(ETHERTYPE_IP);
    fwrite(&eth_header, sizeof(eth_header), 1, f_savefile);

    /* write the IP/TCP parts */
    wlen = phdr.caplen - EH_SIZE;	/* remove the ether header */
    fwrite(pip, wlen, 1, f_savefile);
}
    


#else /* GROK_TCPDUMP */

void
PcapSavePacket(
    char *filename,
    struct ip *pip,
    void *plast)
{
    fprintf(stderr,"\
Sorry, packet writing only supported with the pcap library\n\
compiled into the program (See GROK_TCPDUMP)\n");
    exit(-2);
}


#endif /* GROK_TCPDUMP */
