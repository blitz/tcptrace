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
/* Added FDDI support 9/96 Jeffrey Semke, Pittsburgh Supercomputing Center */
static char const rcsid_tcpdump[] =
    "@(#)$Header$";


#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#define	SWAPSHORT(y) \
	( (((y)&0xff)<<8) | (((y)&0xff00)>>8) )



/* (from bpf.h)
 * Data-link level type codes.
 */

/* Note - Tue Feb 13, 2001
   We're having trouble with the standard DLT_type because some OS versions,
   insist on renumbering these to different values.  To avoid the problem,
   we're hijacking the types a little and adding the PCAP_ prefix.  The
   constants all correspond to the "true" pcap numbers, so this should
   fix the problem */

/* currently supported */
#define PCAP_DLT_NULL		0	/* no link-layer encapsulation */
#define PCAP_DLT_EN10MB		1	/* Ethernet (10Mb) */
#define PCAP_DLT_IEEE802	6	/* IEEE 802 Networks */
#define PCAP_DLT_SLIP		8	/* Serial Line IP */
#define PCAP_DLT_FDDI		10	/* FDDI */
#define PCAP_DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define PCAP_DLT_RAW		12	/* raw IP */
#define PCAP_DLT_IEEE802_11     105     /* IEEE 802.11 wireless */
#define PCAP_DLT_LINUX_SLL      113     /* Linux cooked socket */
#define PCAP_DLT_PRISM2         119     /* Prism2 raw capture header */
#define PCAP_DLT_IEEE802_11_RADIO 127   /* 802.11 plus WLAN header */

/* NOT currently supported */
/* (mostly because I don't have an example file, send me one...) */
#define PCAP_DLT_EN3MB		2	/* Experimental Ethernet (3Mb) */
#define PCAP_DLT_AX25		3	/* Amateur Radio AX.25 */
#define PCAP_DLT_PRONET		4	/* Proteon ProNET Token Ring */
#define PCAP_DLT_CHAOS		5	/* Chaos */
#define PCAP_DLT_ARCNET		7	/* ARCNET */
#define PCAP_DLT_PPP		9	/* Point-to-point Protocol */
#define PCAP_DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define PCAP_DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */



/* tcpdump file header */
#define TCPDUMP_MAGIC 0xa1b2c3d4

struct dump_file_header {
	u_int	magic;
	u_short version_major;
	u_short version_minor;
	int	thiszone;	/* gmt to local correction */
	u_int	sigfigs;	/* accuracy of timestamps */
	u_int	snaplen;	/* max length saved portion of each pkt */
	u_int	linktype;	/* data link type (PCAP_DLT_*) */
};


/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct packet_header {
	u_int	ts_secs;	/* time stamp -- seconds */
	u_int	ts_usecs;	/* time stamp -- useconds */
	u_int	caplen;		/* length of portion present */
	u_int	len;		/* length of this packet (off wire) */
};


#ifdef BY_HAND
static void
swap_hdr(struct dump_file_header *pdfh)
{
    pdfh->version_major = SWAPSHORT(pdfh->version_major);
    pdfh->version_minor = SWAPSHORT(pdfh->version_minor);
    pdfh->thiszone      = SWAPLONG(pdfh->thiszone);
    pdfh->sigfigs       = SWAPLONG(pdfh->sigfigs);
    pdfh->snaplen       = SWAPLONG(pdfh->snaplen);
    pdfh->linktype      = SWAPLONG(pdfh->linktype);
}

static void
swap_phdr(struct packet_header *pph)
{
    pph->caplen   = SWAPLONG(pph->caplen);
    pph->len	  = SWAPLONG(pph->len);
    pph->ts_secs  = SWAPLONG(pph->ts_secs);
    pph->ts_usecs = SWAPLONG(pph->ts_usecs);
}
#endif /* BY_HAND */




/* (Courtesy Jeffrey Semke, Pittsburgh Supercomputing Center) */
/* locate ip within FDDI according to RFC 1188 */
static int find_ip_fddi(char* buf, int iplen) {
      char* ptr, *ptr2;
      int i;
      u_char pattern[] = {0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
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
