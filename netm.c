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


/* 
 * netm.c - NetMetrix specific file reading stuff
 */


#include "tcptrace.h"


#ifdef GROK_NETM

#define NETM_DUMP_OFFSET 0x1000


/* netm file header format */
struct netm_header {
	int	netm_key;
	int	version;
};
#define NETM_VERSION_OLD 3
#define NETM_VERSION_NEW 4
#define NETM_KEY 0x6476


/* netm packet header format */
struct netm_packet_header_old {
    int	unused1;
    int	unused2;
    int	tstamp_secs;
    int	tstamp_usecs;
    int	tlen;
    int	len;
};
struct netm_packet_header {
    int	unused1;
    int	tstamp_secs;
    int	tstamp_usecs;
    int	unused2;
    int	unused3;
    int	len;
    int	tlen;  /* truncated length */
    int	unused5;
};


/* netm packet header format */

int netm_oldversion;


/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;


/* currently only works for ETHERNET */
static int
pread_netm(
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
    struct netm_packet_header hdr;
    int len;
    int hlen;

    while (1) {
	hlen = netm_oldversion?
	    (sizeof(struct netm_packet_header_old)):
	    (sizeof(struct netm_packet_header));

	/* read the netm packet header */
	if ((rlen=fread(&hdr,1,hlen,stdin)) != hlen) {
	    if (rlen != 0)
		fprintf(stderr,"Bad netm header\n");
	    return(0);
	}

	packlen = ntohl(hdr.tlen);
	/* round up to multiple of 4 bytes */
	len = (packlen + 3) & ~0x3;

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
		    "pread_netm: invalid next packet, IP len is %d, return EOF\n", len);
	    return(0);
	}
	if ((rlen=fread(pip_buf,1,len,stdin)) != len) {
	    if (rlen != 0)
		if (debug)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
	    return(0);
	}

	if (netm_oldversion) {
	    struct netm_packet_header_old *pho;
	    pho = (struct netm_packet_header_old *) &hdr;

	    ptime->tv_sec  = ntohl(pho->tstamp_secs);
	    ptime->tv_usec = ntohl(pho->tstamp_usecs);
	    *plen          = ntohl(pho->len);
	    *ptlen         = ntohl(pho->tlen);
	} else {
	    ptime->tv_sec  = ntohl(hdr.tstamp_secs);
	    ptime->tv_usec = ntohl(hdr.tstamp_usecs);
	    *plen          = ntohl(hdr.len);
	    *ptlen         = ntohl(hdr.tlen);
	}


	*ppip  = (struct ip *) pip_buf;
	*pplast = (char *)pip_buf+packlen-sizeof(struct ether_header)-1; /* last byte in the IP packet */
	*pphys  = pep;
	*pphystype = PHYS_ETHER;


	/* if it's not IP, then skip it */
	if ((ntohs(pep->ether_type) != ETHERTYPE_IP) &&
	    (ntohs(pep->ether_type) != ETHERTYPE_IPV6)) {
	    if (debug > 2)
		fprintf(stderr,"pread_netm: not an IP packet\n");
	    continue;
	}

	return(1);
    }
}



/* is the input file a NetMetrix format file?? */
pread_f *is_netm(void)
{
    struct netm_header nhdr;
    int rlen;

    /* read the netm file header */
    if ((rlen=fread(&nhdr,1,sizeof(nhdr),stdin)) != sizeof(nhdr)) {
	rewind(stdin);
	return(NULL);
    }
    rewind(stdin);

    /* convert to local byte order */
    nhdr.netm_key = ntohl(nhdr.netm_key);
    nhdr.version = ntohl(nhdr.version);

    /* check for NETM */
    if (nhdr.netm_key != NETM_KEY) {
	return(NULL);
    }


    /* check version */
    if (nhdr.version == NETM_VERSION_OLD)
	netm_oldversion = 1;
    else if (nhdr.version == NETM_VERSION_NEW)
	netm_oldversion = 0;
    else {
	fprintf(stderr,"Bad NETM file header version: %d\n",
		nhdr.version);
	return(NULL);
    }

    if (debug)
	printf("NETM file version: %d\n", nhdr.version);

    /* ignore the header at the top */
    if (fseek(stdin,NETM_DUMP_OFFSET,SEEK_SET) == -1) {
	perror("NETM lseek");
	exit(-1);
    }

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_netm);
}

#endif /* GROK_NETM */

