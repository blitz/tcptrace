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
    "@(#)Copyright (c) 1996 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/* 
 * snoop.c - SNOOP specific file reading stuff
 */


#include "tcptrace.h"


#ifdef GROK_SNOOP

/* information necessary to understand Solaris Snoop output */
#define SNOOP_DUMP_OFFSET 16
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


/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_snoop(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip)
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

	ptime->tv_sec  = hdr.secs;
	ptime->tv_usec = hdr.usecs;
	*plen          = hdr.len;
	*ptlen         = hdr.tlen;


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



/*
 * is_snoop()   is the input file in snoop format??
 */
int (*is_snoop(void))()
{
    char buf[20];
    int rlen;

    /* read the snoop file header */
    if ((rlen=fread(buf,1,5,stdin)) != 5) {
	rewind(stdin);
	return(NULL);
    }
    rewind(stdin);

    if (strncmp(buf,"snoop",5) != 0)
	return(NULL);

    /* OK, it's a snoop file */

    /* ignore the header at the top */
    if (fseek(stdin,SNOOP_DUMP_OFFSET,SEEK_SET) == -1) {
	perror("lseek");
	exit(-1);
    }

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_snoop);
}
#endif /* GROK_SNOOP */
