/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
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
static char const GCC_UNUSED rcsid_ipv6[] =
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
#if !defined(IPPROTO_NONE) && !defined(IPPROTO_FRAGMENT) && !defined(IPPROTO_DSTOPTS) && !defined(INET6_ADDRSTRLEN)
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
#ifdef __WIN32
typedef struct in6_addr {
	u_char	s6_addr[16];	/* IPv6 address */
} in6_addr;
#endif /* __WIN32 */

#endif /* notdef IPPROTO_NONE */


/*
 * IPv6 datagram header 
 */
struct ipv6 {
    u_int ip6_ver_tc_flabel;	/* first 4  bits = version #, 
                                   next  8  bits = Trafic class,
				   next  20 bits = flow label */
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
    u_char	ip6ext_data[2];	/* optional data */
};


/* IPv6 fragmentation header */
struct ipv6_ext_frag {
    u_char	ip6ext_fr_nheader;	/* Next Header */
    u_char	ip6ext_fr_res;	/* (reserved) */
    u_short	ip6ext_fr_offset; /* fragment offset(13),res(2),M(1) */
    u_long	ip6ext_fr_ID;	/* ID field */
};


/* tcptrace's IPv6 access routines */
int gettcp(struct ip *pip, struct tcphdr **pptcp, void **pplast);
int getudp(struct ip *pip, struct udphdr **ppudp, void **pplast);
int getroutingheader(struct ip *pip, struct ipv6_ext **ppipv6_ext, void **pplast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
struct ipv6_ext *ipv6_nextheader(void *pheader0, u_char *pnextheader);
char *ipv6_header_name(u_char nextheader);
char *my_inet_ntop(int af, const char *src, char *dst, size_t size);
int total_length_ext_headers(struct ipv6 *pip6);
  
