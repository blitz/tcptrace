/*
 * Copyright (c) 1994, 1995, 1996
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
    "@(#)Copyright (c) 1996\nOhio University.  All rights reserved.\n";
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
#define VERSION_OLD 3
#define VERSION_NEW 4
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
    struct ip		**ppip)
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

	packlen = hdr.tlen;
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
	if ((rlen=fread(pip_buf,1,len,stdin)) != len) {
	    if (rlen != 0)
		fprintf(stderr,
			"Couldn't read %d more bytes, skipping last packet\n",
			len);
	    return(0);
	}

	if (netm_oldversion) {
	    struct netm_packet_header_old *pho;
	    pho = (struct netm_packet_header_old *) &hdr;

	    ptime->tv_sec  = pho->tstamp_secs;
	    ptime->tv_usec = pho->tstamp_usecs;
	    *plen          = pho->len;
	    *ptlen         = pho->tlen;
	} else {
	    ptime->tv_sec  = hdr.tstamp_secs;
	    ptime->tv_usec = hdr.tstamp_usecs;
	    *plen          = hdr.len;
	    *ptlen         = hdr.tlen;
	}


	*ppip  = (struct ip *) pip_buf;
	*pphys  = pep;
	*pphystype = PHYS_ETHER;


	/* if it's not TCP/IP, then skip it */
	if ((pep->ether_type != ETHERTYPE_IP) ||
	    ((*ppip)->ip_p != IPPROTO_TCP))
	    continue;


	return(1);
    }
}



/* is the input file a NetMetrix format file?? */
int (*is_netm(void))()
{
    struct netm_header nhdr;
    int rlen;

    /* read the netm file header */
    if ((rlen=fread(&nhdr,1,sizeof(nhdr),stdin)) != sizeof(nhdr)) {
	rewind(stdin);
	return(NULL);
    }
    rewind(stdin);

    /* check for NETM */
    if (nhdr.netm_key != NETM_KEY) {
	return(NULL);
    }


    /* check version */
    if (nhdr.version == VERSION_OLD)
	netm_oldversion = 1;
    else if (nhdr.version == VERSION_NEW)
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

#endif GROK_NETM

