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
static char const rcsid_ipv6[] =
    "@(#)$Header$";


/*
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD	/* Ethernet type for ipv6 */
#endif

/* just guessing... */
#if !defined(IPPROTO_NONE) && !defined(IPPROTO_FRAGMENT) && !defined(IPPROTO_DSTOPTS)
/* when IPv6 is more widely/standardly deployed, these constants won't need to be
   here.  In the mean time, here's the stuff we need... */
#define IPV6NOTFOUND

/* header types */
#define	IPPROTO_HOPOPTS		0		/* Hop by hop header for v6 */
#define	IPPROTO_IPV6		41		/* IPv6 encapsulated in IP */
#define	IPPROTO_ROUTING		43		/* Routing header for IPv6 */
#define	IPPROTO_FRAGMENT	44		/* Fragment header for IPv6 */
#define	IPPROTO_ICMPV6		58		/* ICMP for IPv6 */
#define	IPPROTO_NONE		59		/* No next header for IPv6 */
#define	IPPROTO_DSTOPTS		60		/* Destinations options */

/* other constants we need */
#define INET6_ADDRSTRLEN        46              /* IPv6 Address length in a string format*/

/* this is SOMETIMES already defined */
#ifndef AF_INET6
#define AF_INET6                24              /* Internet Protocol, V6 */
#endif /* AF_INET6 */



/*
 * IPv6 address data structure.
 */
typedef struct in6_addr {
	u_char	s6_addr[16];	/* IPv6 address */
} in6_addr;


/* external routines that we use if found, otherwise substitute our own... */
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int, const char *, char *, size_t);
#endif /* HAVE_INET_NTOP */

#endif /* notdef IPPROTO_NONE */


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


/* IPv6 extension header format */
struct ipv6_ext {
    u_char	ip6ext_nheader;	/* Next Header */
    u_char	ip6ext_len;	/* number of bytes in this header */
    u_char	ip6ext_data[1];	/* optional data */
};


/* IPv6 fragmentation header */
struct ipv6_ext_frag {
    u_char	ip6ext_fr_nheader;	/* Next Header */
    u_char	ip6ext_fr_res;	/* (reserved) */
    u_short	ip6ext_fr_offset; /* fragment offset(13),res(2),M(1) */
    u_long	ip6ext_fr_ID;	/* ID field */
};


/* tcptrace's IPv6 access routines */
struct tcphdr *gettcp(struct ip *pip, void **pplast);
struct udphdr *getudp(struct ip *pip, void **pplast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
struct ipv6_ext *ipv6_nextheader(void *pheader0, u_char *pnextheader);
char *ipv6_header_name(u_char nextheader);
