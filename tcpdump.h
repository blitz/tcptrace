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

/* currently supported */
#define DLT_NULL	0	/* no link-layer encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_FDDI	10	/* FDDI */
#define DLT_RAW		12	/* raw IP */

/* NOT currently supported */
/* (mostly because I don't have an example file, send me one...) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* IEEE 802 Networks */
#define DLT_ARCNET	7	/* ARCNET */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */



/* tcpdump file header */
#define TCPDUMP_MAGIC 0xa1b2c3d4
struct dump_file_header {
	u_int	magic;
	u_short version_major;
	u_short version_minor;
	int	thiszone;	/* gmt to local correction */
	u_int	sigfigs;	/* accuracy of timestamps */
	u_int	snaplen;	/* max length saved portion of each pkt */
	u_int	linktype;	/* data link type (DLT_*) */
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
