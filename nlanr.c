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
 * nlanr - TSH specific file reading stuff
 */

/* TSH header format:
 *        0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 0  |                    timestamp (seconds)                        | Time
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 1  |  interface #  |          timestamp (microseconds)             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 2  |Version|  IHL  |Type of Service|          Total Length         | IP
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 3  |         Identification        |Flags|      Fragment Offset    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 4  |  Time to Live |    Protocol   |         Header Checksum       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 5  |                       Source Address                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 6  |                    Destination Address                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 7  |          Source Port          |       Destination Port        | TCP
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 8  |                        Sequence Number                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 9  |                    Acknowledgment Number                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Data |           |U|A|P|R|S|F|                               |
 * 10 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *    |       |           |G|K|H|T|N|N|                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */



#include "tcptrace.h"


#ifdef GROK_NLANR

/* information necessary to understand NLANL Tsh output */
#define TSH_DUMP_OFFSET 16
struct tsh_packet_header {
    unsigned int	ts_secs;
#ifdef _BIT_FIELDS_LTOH
    unsigned int	interface_id:8;
    unsigned int	ts_usecs:24;
#else
    unsigned int	ts_usecs:24;
    unsigned int	interface_id:8;
#endif
};

struct tsh_frame {
    struct tsh_packet_header tph;
    struct ip ip_header;
    struct tcphdr tcp_header;  /* just the first 16 bytes present */
};


/* static buffers for reading */
static struct ether_header *pep;

/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_nlanr(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int rlen;
    static struct tsh_frame hdr;
    int packlen = sizeof(struct ip) + sizeof(struct tcphdr);
    int hlen = 44;

    /* read the next frames */
    if ((rlen=fread(&hdr,1,hlen,stdin)) != hlen) {
	if (rlen != 0)
	    fprintf(stderr,"Bad tsh packet header (len:%d)\n", rlen);
	return(0);
    }

    /* grab the time */
    ptime->tv_sec  = hdr.tph.ts_secs;
    ptime->tv_usec = hdr.tph.ts_usecs;

    /* truncated length is just an IP header and a TCP header */
    *ptlen         = packlen;

    /* original length is from the IP header */
    *plen          = hdr.ip_header.ip_len;


    /* Here's the IP/TCP stuff */
    *ppip  = &hdr.ip_header;

    /* Here's the last byte of the packet */
    *pplast = (char *)(*ppip)+packlen-1;

    /* here's the (pseudo) ethernet header */
    *pphys  = pep;
    *pphystype = PHYS_ETHER;

    return(1);
}



/*
 * is_nlanr()   is the input file in tsh format??
 */
pread_f *is_nlanr(void)
{
    struct tsh_frame tf;
    int rlen;

    /* tsh is a little hard because there's no magic number */
    

    /* read the tsh file header */
    if ((rlen=fread(&tf,1,sizeof(tf),stdin)) != sizeof(tf)) {
	/* not even a full frame */
	rewind(stdin);
	return(NULL);
    }
    rewind(stdin);

    if (debug) {
	printf("nlanr tsh ts_secs:   %d\n", tf.tph.ts_secs);
	printf("nlanr tsh ts_usecs:  %d\n", tf.tph.ts_usecs);
	printf("nlanr tsh interface: %d\n", tf.tph.interface_id);
	printf("nlanr sizeof(tf):    %d\n", sizeof(tf));
	printf("nlanr sizeof(tph):   %d\n", sizeof(tf.tph));
	if (debug > 1)
	    PrintRawDataHex("NLANR TSH header",&tf,(char *)&tf+39);
    }

    /* quick heuristics */
    if (((tf.ip_header.ip_v != 4) && (tf.ip_header.ip_v != 6))
	) {
	return(NULL);
    }


    /* OK, let's hope it's a tsh file */


    /* there's no physical header present, so make up one */
    pep = MallocZ(sizeof(struct ether_header));
    pep->ether_type = htons(ETHERTYPE_IP);

    if (debug)
	fprintf(stderr,"TSH format, interface ID %d\n", tf.tph.interface_id);


    return(pread_nlanr);
}
#endif /* GROK_NLANR */
