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
 * Author:	Nasseef Abukamail
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 */
static char const copyright[] =
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include "tcptrace.h"

/* the names of IPv6 extensions that we understand */
char *
ipv6_header_name(
    u_char nextheader)
{
    switch (nextheader) {
      case IPPROTO_DSTOPTS: return("Destinations options");
      case IPPROTO_FRAGMENT: return("Fragment header");
      case IPPROTO_HOPOPTS: return("Hop by hop");
      case IPPROTO_NONE: return("No next header");
      case IPPROTO_ROUTING: return("Routing header");
      case IPPROTO_ICMPV6: return("IPv6 ICMP");
      case IPPROTO_TCP: return("TCP");
      case IPPROTO_UDP: return("UDP");
      default:	return("<unknown>");
    }
}


/* given a next header type and a pointer to the header, return a pointer
   to the next extension header and type */
struct ipv6_ext *
ipv6_nextheader(
    void *pheader0,
    u_char *pnextheader)
{
    struct ipv6_ext *pheader = pheader0;
    
    switch (*pnextheader) {
	/* nothing follows these... */
      case IPPROTO_TCP:
      case IPPROTO_NONE:
      case IPPROTO_ICMPV6:
      case IPPROTO_UDP:
	return(NULL);

	/* somebody follows these */
      case IPPROTO_HOPOPTS:
      case IPPROTO_ROUTING:
      case IPPROTO_DSTOPTS:
	*pnextheader = pheader->ip6ext_nheader;

	/* sanity check, if length is 0, terminate */
	if (pheader->ip6ext_len == 0)
	    return(NULL);
	
	return((struct ipv6_ext *)
	       ((char *)pheader + pheader->ip6ext_len));

	/* I don't understand them.  Just save the type and return a NULL */
      default:
	*pnextheader = pheader->ip6ext_nheader;
	return(NULL);
    }
}



/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
static void *
findheader(
    u_int ipproto,
    struct ip *pip,
    void **pplast)
{
    struct ipv6 *pip6 = (struct ipv6 *)pip;
    char nextheader;
    struct ipv6_ext *pheader;
    void *theheader;

    /* IPv4 is easy */
    if (PIP_ISV4(pip)) {
	/* make sure it's what we want */
	if (pip->ip_p != ipproto)
	    return(NULL);

	/* check the fragment field, if it's not the first fragment,
	   it's useless (offset part of field must be 0 */
	if ((ntohs(pip->ip_off)&0x1fff) != 0) {
	    if (debug>1) {
		printf("gettcp: Skipping IPv4 non-initial fragment\n");
		if (debug > 2) {
		    printpacket(100,100,NULL,0,pip,*pplast);
		}
	    }
	    return(NULL);
	}

	/* OK, it starts here */
	theheader = ((char *)pip + 4*pip->ip_hl);

	/* adjust plast in accordance with ip_len (really short packets get garbage) */
	if (((unsigned)pip + ntohs(pip->ip_len) - 1) < (unsigned)(*pplast)) {
	    *pplast = (void *)((unsigned)pip + ntohs(pip->ip_len));
	}

#ifdef OLD
	/* this is better verified when used, the error message is better */

	/* make sure the whole header is there */
	if ((u_long)ptcp + (sizeof struct tcphdr) - 1 > (u_long)*pplast) {
	    /* part of the header is missing */
	    return(NULL);
	}
#endif

	return (theheader);
    }

    /* otherwise, we only understand IPv6 */
    if (!PIP_ISV6(pip))
	return(NULL);

    /* find the first header */
    nextheader = pip6->ip6_nheader;
    pheader = (struct ipv6_ext *)(pip6+1);

    /* loop until we find the header we want or give up */
    while (1) {
	/* sanity check, if we're reading bogus header, the length might */
	/* be wonky, so make sure before you dereference anything!! */
	if ((void *)pheader < (void *)pip) {
	    if (debug>1)
		printf("findheader: bad extension header math, skipping packet\n");
	    return(NULL);
	}
	
	/* make sure we're still within the packet */
	/* might be truncated, or might be bad header math */
	if ((void *)pheader > *pplast) {
	    if (debug>3)
		printf("findheader: packet truncated before finding header\n");
	    return(NULL);
	}

	/* this is what we want */
	if (nextheader == ipproto)
	    return(pheader);

	switch (nextheader) {
	  case IPPROTO_TCP:
	    return(NULL);	/* didn't find it */
	  case IPPROTO_UDP:
	    return(NULL);	/* didn't find it */

	    /* non-tcp protocols */
	  case IPPROTO_NONE:
	  case IPPROTO_ICMPV6:

	    /* fragmentation */
	  case IPPROTO_FRAGMENT:
	  {
	      struct ipv6_ext_frag *pfrag = (struct ipv6_ext_frag *)pheader;

	      /* if this isn't the FIRST fragment, there won't be a TCP header
		 anyway */
	      if ((pfrag->ip6ext_fr_offset&0xfc) != 0) {
		  /* the offset is non-zero */
		  if (debug>1)
		      printf("gettcp: Skipping IPv6 non-initial fragment\n");
		  return(NULL);
	      }

	      /* otherwise it's either an entire segment or the first fragment */
	      nextheader = pheader->ip6ext_nheader;
	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + pheader->ip6ext_len);
	      break;
	  }

	  /* headers we just skip over */
	  case IPPROTO_HOPOPTS:
	  case IPPROTO_ROUTING:
	  case IPPROTO_DSTOPTS:
	      nextheader = pheader->ip6ext_nheader;
	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + pheader->ip6ext_len);
	      break;

	  /* I "think" that we can just skip over it, but better be careful */
	  default:
	      nextheader = pheader->ip6ext_nheader;
	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + pheader->ip6ext_len);
	      break;

	} /* end switch */
    }  /* end loop */

    /* shouldn't get here, but just in case :-) */
    return NULL;
}


/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
struct tcphdr *
gettcp(
    struct ip *pip,
    void **pplast)
{
    struct tcphdr *ptcp;
    ptcp = (struct tcphdr *)findheader(IPPROTO_TCP,pip,pplast);
    return(ptcp);
}


/*
 * getudp:  return a pointer to a udp header.
 * Skips either ip or ipv6 headers
 */
struct udphdr *
getudp(
    struct ip *pip,
    void **pplast)
{
    struct udphdr *pudp;
    pudp = (struct udphdr *)findheader(IPPROTO_UDP,pip,pplast);
    return(pudp);
}



/* 
 * gethdrlength: returns the length of the header in the case of ipv4
 *               returns the length of all the headers in the case of ipv6
 */
int gethdrlength (struct ip *pip, void *plast)
{
    int length, nextheader;
    char *pheader;
    struct ipv6 *pipv6;
    
    if (PIP_ISV6(pip)) {
	length = 40;
	
	pheader = (char *) pip;
	nextheader = *(pheader + 6);
	pheader += 40;
	
	pipv6 = (struct ipv6 *) pip;
	while (1)
	{
	    if (nextheader == IPPROTO_NONE)
		return length;
	    if (nextheader == IPPROTO_TCP)
		return length;
	    if (nextheader == IPPROTO_UDP)
		return length;
	    if (nextheader == IPPROTO_FRAGMENT)
	    {
		nextheader = *pheader;
		pheader += 8;
		length += 8;
	    }
	    if ((nextheader == IPPROTO_HOPOPTS) || (nextheader == IPPROTO_ROUTING)
		|| (nextheader == IPPROTO_DSTOPTS))
	    {
		nextheader = *pheader;
		pheader += *(pheader + 1);
		length += *(pheader + 1);
	    }
	    if (pheader > (char *)plast)
		return -1;
	}
    }
    else
    {
	return pip->ip_hl * 4;
    }
}

/*
 * getpayloadlength: returns the length of the packet without the header.
 */ 
int getpayloadlength (struct ip *pip, void *plast)
{
    struct ipv6 *pipv6;
    
    if (PIP_ISV6(pip)) {
	pipv6 = (struct ipv6 *) pip;  /* how about all headers */
	return ntohs(pipv6->ip6_lngth);
    }
    return ntohs(pip->ip_len) - (pip->ip_hl * 4);
}



/* 
 * ipcopyaddr: copy an IPv4 or IPv6 address  
 */
void IP_COPYADDR (ipaddr *toaddr, ipaddr fromaddr)
{
    if (ADDR_ISV6(&fromaddr)) {
	memcpy(toaddr->un.ip6.s6_addr, fromaddr.un.ip6.s6_addr, 16);
	toaddr->addr_vers = 6;
    } else {
	toaddr->un.ip4.s_addr = fromaddr.un.ip4.s_addr;
	toaddr->addr_vers = 4;
    }
}



/*
 * ipsameaddr: test for equality of two IPv4 or IPv6 addresses
 */
int IP_SAMEADDR (ipaddr addr1, ipaddr addr2)
{
    int ret = 0;
    if (ADDR_ISV6(&addr1)) {
	if (ADDR_ISV6(&addr2))
	    ret = (memcmp(addr1.un.ip6.s6_addr,
			  addr2.un.ip6.s6_addr,16) == 0);
    } else {
	if (ADDR_ISV4(&addr2))
	    ret = (addr1.un.ip4.s_addr == addr2.un.ip4.s_addr);
    }
    if (debug > 3)
	printf("SameAddr(%s(%d),%s(%d)) returns %d\n",
	       HostName(addr1), ADDR_VERSION(&addr1),
	       HostName(addr2), ADDR_VERSION(&addr2),
	       ret);
    return ret;
}



#ifndef HAVE_INET_PTON
int
inet_pton(int af, const char *src, void *dst)
{
    if (af == AF_INET) {
	/* use standard function */
	long answer = inet_addr(src);
	if (answer != -1) {
	    *((long *)dst) = answer;
	    return(1);
	}
    } else if (af == AF_INET6) {
	/* YUCC - lazy for now, not fully supported */
	int shorts[8];
	if (sscanf(src,"%x:%x:%x:%x:%x:%x:%x:%x",
		   &shorts[0], &shorts[1], &shorts[2], &shorts[3],
		   &shorts[4], &shorts[5], &shorts[6], &shorts[7]) == 8) {
	    int i;
	    for (i=0; i < 8; ++i)
		((u_short *)dst)[i] = (u_short)shorts[i];
	    return(1);
	}
    }

    /* else, it failed */
    return(0);
}
#endif /* HAVE_INET_PTON */



#ifndef HAVE_INET_NTOP
/*
 * inet_ntop: makes a string address of the 16 byte ipv6 address
 */
const char *inet_ntop(int af, const char *src, char *dst, size_t size)
{
    int i;
    u_short s;
    char *temp;

    temp = dst;
    for (i = 0; i < 16; i++)
    {
	s = (u_short)  src[i];
	sprintf(dst, "%02x",(s & 0x00ff));  /* make the hi order byte 0 */
	s = (u_short) src[++i];
	dst += 2;
	sprintf(dst, "%02x", (s & 0x00ff));
	dst += 3;
	*(dst - 1) = ':';
    }
    *(dst-1) = '\0';
    dst = temp;
    return dst;
}
#endif /* HAVE_INET_NTOP */


/* given an IPv4 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV4ADDR2ADDR(
    struct in_addr *addr4)
{
    static struct ipaddr addr;

    addr.addr_vers = 4;
    addr.un.ip4.s_addr = addr4->s_addr;

    return(&addr);
}


/* given an IPv6 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV6ADDR2ADDR(
    struct in6_addr *addr6)
{
    static struct ipaddr addr;

    addr.addr_vers = 6;
    memcpy(&addr.un.ip6.s6_addr,&addr6->s6_addr, 16);

    return(&addr);
}


/* given an internet address (IPv4 dotted decimal or IPv6 hex colon),
   return an "ipaddr" (allocated from heap) */
ipaddr *
str2ipaddr(
    char *str)
{
    ipaddr *pipaddr;

    /* allocate space */
    pipaddr = MallocZ(sizeof(ipaddr));

    /* N.B. - uses standard IPv6 facility inet_pton from RFC draft */
    if (strchr(str,'.') != NULL) {
	/* has dots, better be IPv4 */
	pipaddr->addr_vers = 4;
	if (inet_pton(AF_INET, str,
		      &pipaddr->un.ip4.s_addr) != 1) {
	    if (debug)
		fprintf(stderr,"Address string '%s' unparsable as IPv4\n",
			str);
	    return(NULL);
	}
    } else if (strchr(str,':') != NULL) {
	/* has colons, better be IPv6 */
	pipaddr->addr_vers = 6;
	if (inet_pton(AF_INET6, str, 
		      &pipaddr->un.ip6.s6_addr) != 1) {
	    if (debug)
		fprintf(stderr,"Address string '%s' unparsable as IPv6\n",
			str);
	    return(NULL);
	}
    } else {
	if (debug)
	    fprintf(stderr,"Address string '%s' unparsable\n", str);
	return(NULL);
    }

    return(pipaddr);
}
