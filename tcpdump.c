/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
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
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
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
      case PCAP_DLT_EN10MB:
	memcpy(&eth_header,buf,EH_SIZE);  /* save ether header */
	memcpy(ip_buf,buf+EH_SIZE,iplen);
	callback_plast = (char *)ip_buf+iplen-EH_SIZE-1;
	break;
      case PCAP_DLT_IEEE802:
	/* just pretend it's "normal" ethernet */
	offset = 14;		/* 22 bytes of IEEE cruft */
	memcpy(&eth_header,buf,EH_SIZE);  /* save ether header */
	memcpy(ip_buf,buf+offset,iplen);
	callback_plast = (char *)ip_buf+iplen-offset-1;
	break;
      case PCAP_DLT_SLIP:
	memcpy(ip_buf,buf+16,iplen);
	callback_plast = (char *)ip_buf+iplen-16-1;
	break;
      case PCAP_DLT_FDDI:
	if (offset < 0)
	      offset = find_ip_fddi(buf,iplen);
	if (offset < 0)
	      return(-1);
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      case PCAP_DLT_NULL:
	/* no phys header attached */
	offset = 4;
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      case PCAP_DLT_ATM_RFC1483:
	/* ATM RFC1483 - LLC/SNAP ecapsulated atm */
	memcpy((char *)ip_buf,buf+8,iplen);
	callback_plast = ip_buf+iplen-8-1;
	break;
      case PCAP_DLT_RAW:
	/* raw IP */
	offset = 0;
	memcpy((char *)ip_buf,buf+offset,iplen);
	callback_plast = ip_buf+iplen-offset-1;
	break;
      case PCAP_DLT_LINUX_SLL:
	/* linux cooked socket */
	offset = 16;
	memcpy((char *)ip_buf, buf+offset, iplen);
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
	/* (copying time structure in 2 steps to avoid RedHat brain damage) */
	ptime->tv_usec = callback_phdr->ts.tv_usec;
	ptime->tv_sec = callback_phdr->ts.tv_sec;
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
      case PCAP_DLT_EN10MB:
	/* OK, we understand this one */
	physname = "Ethernet";
	break;
      case PCAP_DLT_IEEE802:
	/* just pretend it's normal ethernet */
	physname = "Ethernet";
	break;
      case PCAP_DLT_SLIP:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "Slip";
	break;
      case PCAP_DLT_FDDI:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "FDDI";
	break;
      case PCAP_DLT_NULL:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "NULL";
	break;
      case PCAP_DLT_ATM_RFC1483:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "ATM, LLC/SNAP encapsulated";
	break;
      case PCAP_DLT_RAW:
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "RAW_IP";
	break;
      case PCAP_DLT_LINUX_SLL:
	/* linux cooked socket type */
	eth_header.ether_type = htons(ETHERTYPE_IP);
	physname = "Linux Cooked Socket";
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
    static MFILE *f_savefile = NULL;
    struct pcap_pkthdr phdr;
    int wlen;

    if (f_savefile == NULL) {
	struct pcap_file_header fhdr;

	/* try to open the file */
	if ((f_savefile = Mfopen(filename, "w")) == NULL) {
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
	fhdr.linktype = PCAP_DLT_EN10MB; /* always Ethernet (10Mb) */
	fhdr.sigfigs = 0;

	/* write the header */
	Mfwrite((char *)&fhdr, sizeof(fhdr), 1, f_savefile);

	if (debug)
	    fprintf(stderr,"Created pcap save file '%s'\n", filename);
    }

    /* create the packet header */
    /* (copying time structure in 2 steps to avoid RedHat brain damage) */
    phdr.ts.tv_sec = current_time.tv_sec;
    phdr.ts.tv_usec = current_time.tv_usec;
    phdr.caplen = (char *)plast - (char *)pip + 1;
    phdr.caplen += EH_SIZE;	/* add in the ether header */
    phdr.len = EH_SIZE + ntohs(PIP_LEN(pip));	/* probably this */

    /* write the packet header */
    Mfwrite(&phdr, sizeof(phdr), 1, f_savefile);

    /* write a (bogus) ethernet header */
    memset(&eth_header,0,EH_SIZE);
    eth_header.ether_type = htons(ETHERTYPE_IP);
    Mfwrite(&eth_header, sizeof(eth_header), 1, f_savefile);

    /* write the IP/TCP parts */
    wlen = phdr.caplen - EH_SIZE;	/* remove the ether header */
    Mfwrite(pip, wlen, 1, f_savefile);
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
