/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
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
    "@(#)Copyright (c) 1998 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * snoop.c - SNOOP specific file reading stuff
 *	ipv6 addition by Nasseef Abukamail
 */


#include "tcptrace.h"


#ifdef GROK_SNOOP

/* information necessary to understand Solaris Snoop output */
struct snoop_file_header {
    char		format_name[8];	/* should be "snoop\0\0\0" */
    u_int		snoop_version;	/* current version is "2" */
    u_int		mac_type;	/* hardware type */
};
/* snoop hardware types that we understand */
/* from sys/dlpi.h */
/*  -- added prefix SNOOP_ to avoid name clash */
#define	SNOOP_DL_ETHER	0x4	/* Ethernet Bus */
#define	SNOOP_DL_FDDI	0x08	/* Fiber Distributed data interface */

struct snoop_packet_header {
    unsigned int	len;
    unsigned int	tlen;
    unsigned int	unused2;
    unsigned int	unused3;
    unsigned int	secs;
    unsigned int	usecs;
};



/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;
static int snoop_mac_type;

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


/* return the next packet header */
/* currently only works for ETHERNET and FDDI */
static int
pread_snoop(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int packlen;
    int rlen;
    int len;
    struct snoop_packet_header hdr;
    int hlen;

    while (1) {
	hlen = sizeof(struct snoop_packet_header);

	/* read the packet header */
	if ((rlen=fread(&hdr,1,hlen,stdin)) != hlen) {
	    if (rlen != 0)
		fprintf(stderr,"Bad snoop packet header\n");
	    return(0);
	}

	/* convert some stuff to host byte order */
	hdr.tlen = ntohl(hdr.tlen);
	hdr.len = ntohl(hdr.len);
	hdr.secs = ntohl(hdr.secs);
	hdr.usecs = ntohl(hdr.usecs);

	packlen = hdr.tlen;
	/* round up to multiple of 4 bytes */
	len = (packlen + 3) & ~0x3;

	if (snoop_mac_type == SNOOP_DL_ETHER) {
	    /* read the ethernet header */
	    rlen=fread(pep,1,sizeof(struct ether_header),stdin);
	    if (rlen != sizeof(struct ether_header)) {
		fprintf(stderr,"Couldn't read ether header\n");
		return(0);
	    }

	    /* read the rest of the packet */
	    len -= sizeof(struct ether_header);
	    if (len >= IP_MAXPACKET) {
		/* sanity check */
		fprintf(stderr,
			"pread_snoop: invalid next packet, IP len is %d, return EOF\n", len);
		return(0);
	    }

	    /* if it's not IP, then skip it */
	    if ((ntohs(pep->ether_type) != ETHERTYPE_IP) &&
		(ntohs(pep->ether_type) != ETHERTYPE_IPV6)) {
		if (debug > 2)
		    fprintf(stderr,"pread_snoop: not an IP packet\n");
		continue;
	    }

	    if ((rlen=fread(pip_buf,1,len,stdin)) != len) {
		if (rlen != 0 && debug)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
		return(0);
	    }

	    *ppip  = (struct ip *) pip_buf;
	    /* last byte in the IP packet */
	    *pplast = (char *)pip_buf+packlen-sizeof(struct ether_header)-1;

	} else if (snoop_mac_type == SNOOP_DL_FDDI) {
	    /* FDDI is different */
	    int offset;

	    /* read in the whole frame and search for IP header */
	    /* (assumes sizeof(fddi frame) < IP_MAXPACKET, should be true) */
	    if ((rlen=fread(pip_buf,1,len,stdin)) != len) {
		if (debug && rlen != 0)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
		return(0);
	    }

	    /* find the offset of the IP header inside the FDDI frame */
	    if ((offset = find_ip_fddi((char *)pip_buf,len)) == -1) {
		/* not found */
		if (debug)
		    printf("snoop.c: couldn't find next IP within FDDI\n");
		return(-1);
	    }

	    /* copy to avoid alignment problems later (yucc) */
	    /* (we use memmove to make overlaps work) */
	    memmove(pip_buf,(char *)pip_buf+offset,len-offset);

	    /* point to first and last char in IP packet */
	    *ppip  = (struct ip *) ((char *)pip_buf);
	    *pplast = (char *)pip_buf+len-offset-1;

	    /* assume it's IP (else find_ip_fddi would have failed) */
	    pep->ether_type = htons(ETHERTYPE_IP);
	} else {
	    printf("snoop hardware type %d not understood\n",
		   snoop_mac_type);
	    exit(-1);
	}


	/* save pointer to physical header (always ethernet) */
	*pphys  = pep;
	*pphystype = PHYS_ETHER;


	ptime->tv_sec  = hdr.secs;
	ptime->tv_usec = hdr.usecs;
	*plen          = hdr.len;
	*ptlen         = hdr.tlen;


	return(1);
    }
}



/*
 * is_snoop()   is the input file in snoop format??
 */
pread_f *is_snoop(void)
{
    struct snoop_file_header buf;
    int rlen;

    /* read the snoop file header */
    if ((rlen=fread(&buf,1,sizeof(buf),stdin)) != sizeof(buf)) {
	rewind(stdin);
	return(NULL);
    }

    /* first 8 characters should be "snoop\0\0\0" */
    if (strcmp(buf.format_name,"snoop") != 0)
	return(NULL);

    /* OK, it's a snoop file */


    /* sanity check on snoop version */
    if (debug) {
	printf("Snoop version: %d\n", buf.snoop_version);
    }
    if (buf.snoop_version != 2) {
	printf("\
Warning! snoop file is version %d.\n\
Tcptrace is only known to work with version 2\n",
	       buf.snoop_version);
    }

    /* sanity check on hardware type */
    snoop_mac_type = buf.mac_type;
    switch (buf.mac_type) {
      case SNOOP_DL_ETHER:
	if (debug)
	    printf("Snoop hw type: %d (Ethernet)\n", buf.mac_type);
	break;
      case SNOOP_DL_FDDI:
	if (debug)
	    printf("Snoop hw type: %d (FDDI)\n", buf.mac_type);
	break;
      default:
	if (debug)
	    printf("Snoop hw type: %d (unknown)\n", buf.mac_type);
	printf("snoop hardware type %d not understood\n", buf.mac_type);
	exit(-1);
    }


    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_snoop);
}
#endif /* GROK_SNOOP */
