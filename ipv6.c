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
 * Author:	Nasseef Abukamail
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";



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
  	/* As per RFC 2460 : ip6ext_len specifies the extended
   	 	 header length, in units of 8 octets *not including* the
	 	 first 8 octets.  So ip6ext_len can be 0 and hence,
		 we cannot perform the sanity check any more.

		 Hence commenting out the sanity check - Mani*/
		 
	/* if (pheader->ip6ext_len == 0)
	    return(NULL); */

	return((struct ipv6_ext *)
		   ((char *)pheader + 8 + (pheader->ip6ext_len)*8));

	/* I don't understand them.  Just save the type and return a NULL */
      default:
	*pnextheader = pheader->ip6ext_nheader;
	return(NULL);
    }
}



/*
 * findheader:  find and return a pointer to a header.
 * Skips either ip or ipv6 headers
 * return values:  0 - found header
 *                 1 - correct protocol, invalid packet, cannot return header
 *                -1 - different protocol, cannot return header 
 */
static int
findheader(
    u_int ipproto,
    struct ip *pip,
    void **pphdr,
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
	    return (-1);

	/* check the fragment field, if it's not the first fragment,
	   it's useless (offset part of field must be 0 */
	if ((ntohs(pip->ip_off)&0x1fff) != 0) {
	    if (debug>1) {
		printf("findheader: Skipping IPv4 non-initial fragment\n");
		if (debug > 2) {
		    printpacket(100,100,NULL,0,pip,*pplast,NULL);
		}
	    }
	    return (1);
	}

	/* OK, it starts here */
	theheader = ((char *)pip + 4*IP_HL(pip));

	/* adjust plast in accordance with ip_len (really short packets get garbage) */
	if (((char *)pip + ntohs(pip->ip_len) - 1) < (char *)(*pplast)) {
	    *pplast = (char *)((char *)pip + ntohs(pip->ip_len));
	}

#ifdef OLD
	/* this is better verified when used, the error message is better */

	/* make sure the whole header is there */
	if ((char *)ptcp + (sizeof struct tcphdr) - 1 > (char *)*pplast) {
	    /* part of the header is missing */
	    return (1);
	}
#endif

	*pphdr = theheader;
	return (0);
    }

    /* otherwise, we only understand IPv6 */
    if (!PIP_ISV6(pip))
	return (-1);

    /* find the first header */
    nextheader = pip6->ip6_nheader;
    pheader = (struct ipv6_ext *)(pip6+1);

    /* loop until we find the header we want or give up */
    while (1) {
	/* sanity check, if we're reading bogus header, the length might */
	/* be wonky, so make sure before you dereference anything!! */
	if ((char *)pheader < (char *)pip) {
	    if (debug>1)
		printf("findheader: bad extension header math, skipping packet\n");
	    return (1);
	}
	
	/* make sure we're still within the packet */
	/* might be truncated, or might be bad header math */
	if ((char *)pheader > (char *)*pplast) {
	    if (debug>3)
		printf("findheader: packet truncated before finding header\n");
	    return (1);
	}

	/* this is what we want */
	if (nextheader == ipproto) {
	   *pphdr = pheader;
	   return (0);
	}

	switch (nextheader) {
	  case IPPROTO_TCP:
	    return (-1);	/* didn't find it */
	  case IPPROTO_UDP:
	    return (-1);	/* didn't find it */

	    /* fragmentation */
	  case IPPROTO_FRAGMENT:
	  {
	      struct ipv6_ext_frag *pfrag = (struct ipv6_ext_frag *)pheader;

	      /* if this isn't the FIRST fragment, there won't be a TCP header
		 anyway */
	      if ((pfrag->ip6ext_fr_offset&0xfc) != 0) {
		  /* the offset is non-zero */
		  if (debug>1)
		      printf("findheader: Skipping IPv6 non-initial fragment\n");
		  return (1);
	      }

	      /* otherwise it's either an entire segment or the first fragment */
	      nextheader = pfrag->ip6ext_fr_nheader;
		  /* Pass to the next octet following the fragmentation
		     header */
	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + sizeof(struct ipv6_ext_frag));
	      break;
	  }

	  /* headers we just skip over */
	  case IPPROTO_HOPOPTS:
	  case IPPROTO_ROUTING:
	  case IPPROTO_DSTOPTS:
	      nextheader = pheader->ip6ext_nheader;

		  /* As per RFC 2460 : ip6ext_len specifies the extended
		     header length, in units of 8 octets *not including* the
			 first 8 octets. */
		  
	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + 8 + (pheader->ip6ext_len)*8);
	      break;
	    /* non-tcp protocols, so we're finished. */
	  case IPPROTO_NONE:
	  case IPPROTO_ICMPV6:
	    return (-1);	/* didn't find it */

	  /* I "think" that we can just skip over it, but better be careful */
	  default:
	      nextheader = pheader->ip6ext_nheader;

	      pheader = (struct ipv6_ext *)
		  ((char *)pheader + 8 + (pheader->ip6ext_len)*8);
	      break;

	} /* end switch */
    }  /* end loop */

    /* shouldn't get here, but just in case :-) */
    return (-1);
}

/* Added Aug 31, 2001 -- Avinash.
 * getroutingheader:  return a pointer to the routing header in an ipv6 packet.
 * Looks through all the IPv6 extension headers for the routing header.
 * Used while computing the IPv6 checksums.
 */
int
getroutingheader(
    struct ip *pip,
    struct ipv6_ext **ppipv6_ext,
    void **pplast)
{
    int ret_val = findheader(IPPROTO_ROUTING, pip, (void **)ppipv6_ext, pplast);
    return (ret_val);
}


/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
int
gettcp(
    struct ip *pip,
    struct tcphdr **pptcp,
    void **pplast)
{
    int ret_val = findheader(IPPROTO_TCP, pip, (void **)pptcp, pplast);
    return (ret_val);
}


/*
 * getudp:  return a pointer to a udp header.
 * Skips either ip or ipv6 headers
 */
int
getudp(
    struct ip *pip,
    struct udphdr **ppudp,
    void **pplast)
{
   int ret_val = findheader(IPPROTO_UDP, pip, (void **)ppudp, pplast);
   return (ret_val);
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
	    if ((nextheader == IPPROTO_HOPOPTS) || 
		(nextheader == IPPROTO_ROUTING) ||
		(nextheader == IPPROTO_DSTOPTS))
	    {
	      // Thanks to patch sent by Thomas Bohnert
	      // Header length field in these IPv6 extension headers
	      // stores the length of the header in units of 8 bytes, 
	      // *without* counting the mandatory 8 bytes
	      
	      nextheader = *pheader;
	      length += (*(pheader+1) + 1) * 8;
	      pheader += (*(pheader+1) + 1) * 8;
	    }
	    // IPv6 encapsulated in IPv6
	    if (nextheader == IPPROTO_IPV6)
	    {
	      pheader += 40;
	      nextheader=*(pheader+6);
	      length += 40;
	    }

	  if (pheader > (char *)plast)
		return -1;
	}
    }
    else
    {
	return IP_HL(pip) * 4;
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
    return ntohs(pip->ip_len) - (IP_HL(pip) * 4);
}



#ifdef OLD_THESE_MOVED_TO_TRACE_C
/* 
 * ipcopyaddr: copy an IPv4 or IPv6 address  
 * (note - this is obsolete in favor of the inline-able
 *  IP_COPYADDR in tcptrace.h)
 */
void ip_copyaddr (ipaddr *ptoaddr, ipaddr *pfromaddr)
{
    if (ADDR_ISV6(pfromaddr)) {
	memcpy(ptoaddr->un.ip6.s6_addr, pfromaddr->un.ip6.s6_addr, 16);
	ptoaddr->addr_vers = 6;
    } else {
	ptoaddr->un.ip4.s_addr = pfromaddr->un.ip4.s_addr;
	ptoaddr->addr_vers = 4;
    }
}



/*
 * ipsameaddr: test for equality of two IPv4 or IPv6 addresses
 * (note - this is obsolete in favor of the inline-able
 *  IP_SAMEADDR in tcptrace.h)
 */
int ip_sameaddr (ipaddr *paddr1, ipaddr *paddr2)
{
    int ret = 0;
    if (ADDR_ISV6(paddr1)) {
	if (ADDR_ISV6(paddr2))
	    ret = (memcmp(paddr1->un.ip6.s6_addr,
			  paddr2->un.ip6.s6_addr,16) == 0);
    } else {
	if (ADDR_ISV4(paddr2))
	    ret = (paddr1->un.ip4.s_addr == paddr2->un.ip4.s_addr);
    }
    if (debug > 3)
	printf("SameAddr(%s(%d),%s(%d)) returns %d\n",
	       HostName(*paddr1), ADDR_VERSION(paddr1),
	       HostName(*paddr2), ADDR_VERSION(paddr2),
	       ret);
    return ret;
}

/*  
 *  iplowaddr: test if one IPv4 or IPv6 address is lower than the second one
 * (note - this is obsolete in favor of the inline-able
 *  IP_LOWADDR in tcptrace.h)
 */
int ip_lowaddr (ipaddr *paddr1, ipaddr *paddr2)
{
    int ret = 0;
    if (ADDR_ISV6(paddr1)) {
	if (ADDR_ISV6(paddr2))
	    ret = (memcmp(paddr1->un.ip6.s6_addr,
			  paddr2->un.ip6.s6_addr,16) < 0);
    } else {
	/* already know ADDR_ISV4(paddr1) */
	if (ADDR_ISV4(paddr2))
	    ret = (paddr1->un.ip4.s_addr < paddr2->un.ip4.s_addr);
    }
    if (debug > 3)
	printf("LowAddr(%s(%d),%s(%d)) returns %d\n",
	       HostName(*paddr1), ADDR_VERSION(paddr1),
	       HostName(*paddr2), ADDR_VERSION(paddr2),
	       ret);
    return ret;
}
#endif /* OLD_THESE_MOVED_TO_TRACE_C */


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



/*
 * my_inet_ntop: makes a string address of the 16 byte ipv6 address
 * We use our own because various machines print them differently
 * and I wanted them to all be the same
 */
char *
my_inet_ntop(int af, const char *src, char *dst, size_t size)
{
    int i;
    u_short *src_shorts = (u_short *)src;
    char *ret = dst;
    Bool did_shorthand = FALSE;
    Bool doing_shorthand = FALSE;

    /* sanity check, this isn't general, but doesn't need to be */
    if (size != INET6_ADDRSTRLEN) {
	fprintf(stderr,"my_inet_ntop: invalid size argument\n");
	exit(-1);
    }


    /* address is 128 bits == 16 bytes == 8 shorts */
    for (i = 0; i < 8; i++) {
	u_short twobytes = ntohs(src_shorts[i]);

	/* handle shorthand notation */
	if (twobytes == 0) {
	    if (doing_shorthand) {
		/* just eat it and continue (except last 2 bytes) */
		if (i != 7)
		    continue;
	    } else if (!did_shorthand) {
		/* start shorthand */
		doing_shorthand = TRUE;
		continue;
	    }
	}

	/* terminate shorthand (on non-zero or last 2 bytes) */
	if (doing_shorthand) {
	    doing_shorthand = FALSE;
	    did_shorthand = TRUE;
	    sprintf(dst, ":");
	    dst += 1;
	}

	sprintf(dst, "%04x:", twobytes);
	dst += 5;
    }

    /* nuke the trailing ':' */
    *(dst-1) = '\0';

    return(ret);
}



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


/* compare two IP addresses */
/* result: */
/*    -2: different address types */
/*    -1: A < B */
/*     0: A = B */
/*     1: A > B */
int IPcmp(
    ipaddr *pipA,
    ipaddr *pipB)
{
    int i;
    int len = (pipA->addr_vers == 4)?4:6;
    u_char *left = (u_char *)&pipA->un.ip4;
    u_char *right = (u_char *)&pipB->un.ip4;

    /* always returns -2 unless both same type */
    if (pipA->addr_vers != pipB->addr_vers) {
	if (debug>1) {
	    printf("IPcmp %s", HostAddr(*pipA));
	    printf("%s fails, different addr types\n",
		   HostAddr(*pipB));
	}
	return(-2);
    }


    for (i=0; i < len; ++i) {
	if (left[i] < right[i]) {
	    return(-1);
	} else if (left[i] > right[i]) {
	    return(1);
	}
	/* else ==, keep going */
    }

    /* if we got here, they're the same */
    return(0);
}


/* Added Aug 31, 2001 -- Avinash
 * computes the total length of all the extension headers
 */ 
int total_length_ext_headers(
	struct ipv6 *pip6)
{  
    char nextheader;
    struct ipv6_ext *pheader;
    u_int total_length = 0;
    
    /* find the first header */
    nextheader = pip6->ip6_nheader;
    pheader = (struct ipv6_ext *)(pip6+1);

   
   while(1) {
      switch(nextheader) {
       case IPPROTO_HOPOPTS:
       case IPPROTO_ROUTING:
       case IPPROTO_DSTOPTS:
	 total_length = 8 + (pheader->ip6ext_len * 8);
	 nextheader = pheader->ip6ext_nheader;
	 pheader = (struct ipv6_ext *)
	   ((char *)pheader + 8 + (pheader->ip6ext_len)*8);
	 break;
	 
       case IPPROTO_FRAGMENT:
	 total_length += 8;
	 nextheader = pheader->ip6ext_nheader;
	 pheader = (struct ipv6_ext *)((char *)pheader + 8);
	 break;
       
       case IPPROTO_NONE: /* End of extension headers */
	 return(total_length);
	 
       case IPPROTO_TCP:  /* No extension headers */
	 return(0);
	 
       default:           /* Unknown type */
	 return(-1);
      }
   }
}

