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


/*
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>

#define ETHERTYPE_IPV6 0x86DD	/* Ethernet type for ipv6 */

#ifndef IPV6HDR_NONXTHDR
/* when IPv6 is more widely/standardly deployed, these constants won't need to be
   here.  In the mean time, here's the stuff we need... */
#define IPV6NOTFOUND

/* header types */
#define	IPV6HDR_HOPBYHOP	0		/* Hop by hop header for v6 */
#define	IPPROTO_IPV6		41		/* IPv6 encapsulated in IP */
#define	IPV6HDR_ROUTING		43		/* Routing header for IPv6 */
#define	IPV6HDR_FRAGMENT	44		/* Fragment header for IPv6 */
#define	IPPROTO_ICMPV6		58		/* ICMP for IPv6 */
#define	IPV6HDR_NONXTHDR	59		/* No next header for IPv6 */
#define	IPV6HDR_DSTOPTS		60		/* Destinations options */

/* other constants we need */
#define INET6_ADDRSTRLEN        46              /* IPv6 Address length in a string format*/
#define AF_INET6                24              /* Internet Protocol, V6 */



/*
 * IPv6 address data structure.
 */
typedef struct in6_addr {
	u_char	s6_addr[16];	/* IPv6 address */
} in6_addr;


/* external routines that we use if found, otherwise substutite our own... */
const char *inet_ntop(int, const char *, char *, size_t);

#endif /* notdef IPV6HDR_NONXTHDR */


/*
 * IPv6 datagram header 
 */
struct ipv6 {
    u_int ip6_ver_tc_flabel;	/* first 4  bits = version #, 
                                   next  4  bits = Trafic class,
				   next  24 bits = flow label */
    u_short	ip6_lngth;	/* Payload length */
    u_char	ip6_nheader;	/* Next Header */
    u_char	ip6_hlimit;	/* Hop Limit */
    struct in6_addr ip6_saddr;	/* Source Address */
    struct in6_addr ip6_daddr;	/* Destination Address */
};


/* tcptrace's IPv6 access routines */
struct tcphdr *gettcp(struct ip *pip, void *plast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
