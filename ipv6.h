
/*
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>

#define ETHERTYPE_IPV6 0x86DD	/* Ethernet type for ipv6 */

#ifndef IPV6HDR_NONXTHDR
#define IPV6NOTFOUND
#define	IPV6HDR_HOPBYHOP	0		/* Hop by hop header for v6 */
#define	IPPROTO_IPV6		41		/* IPv6 encapsulated in IP */
#define	IPV6HDR_ROUTING		43		/* Routing header for IPv6 */
#define	IPV6HDR_FRAGMENT	44		/* Fragment header for IPv6 */
#define	IPPROTO_ICMPV6		58		/* ICMP for IPv6 */
#define	IPV6HDR_NONXTHDR	59		/* No next header for IPv6 */
#define	IPV6HDR_DSTOPTS		60		/* Destinations options */
#define AF_INET6                16              /* IPv6 Address length */
#define INET6_ADDRSTRLEN        46              /* IPv6 Address length in a string format*/
/*
 * IPv6 address data structures.
 */

typedef struct in6_addr {
	u_char	s6_addr[16];	/* IPv6 address */
} in6_addr;

const char *inet_ntop(int, const char *, char *, size_t);

#endif


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


/* IPv6 access routines */
struct tcphdr *gettcp(struct ip *pip, void *plast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
