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
 * Author:	Nasseef Abukamail
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 */


#include "tcptrace.h"


/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
struct tcphdr *
gettcp(
    struct ip *pip,
    void *plast)
{
    
    char nextheader;
    char *pheader;

    if (PIP_ISV4(pip)) {
	return (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);
    }

    if (!PIP_ISV6(pip))
	return(NULL);
    
    pheader = (char *) pip;
    nextheader = *(pheader + 6);  /* location of next header in ipv6 header */
    pheader = pheader + 40;    /* point to the next header */
  
    while (1)
    {
	if (nextheader == IPV6HDR_NONXTHDR)
	    return NULL;
	    
	if (nextheader == IPPROTO_TCP)
	    return ((struct tcphdr *) pheader); 
	/* skip the next header */
	if (nextheader == IPV6HDR_FRAGMENT)
	{
	    nextheader = *pheader;
	    pheader += 8;
	    
	}
	if ((nextheader == IPV6HDR_HOPBYHOP) || (nextheader == IPV6HDR_ROUTING)
	    || (nextheader == IPV6HDR_DSTOPTS))
	{
	    nextheader = *pheader;
	    pheader += *(pheader + 1);
	}
	if (pheader > (char *)plast)
	    break;
    }
    return NULL;
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
	    if (nextheader == IPV6HDR_NONXTHDR)
		return length;
	    if (nextheader == IPPROTO_TCP)
		return length;
	    if (nextheader == IPV6HDR_FRAGMENT)
	    {
		nextheader = *pheader;
		pheader += 8;
		length += 8;
	    }
	    if ((nextheader == IPV6HDR_HOPBYHOP) || (nextheader == IPV6HDR_ROUTING)
		|| (nextheader == IPV6HDR_DSTOPTS))
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
    return ntohs(pip->ip_len) - ntohs(pip->ip_hl) * 4;
}



/* 
 * ipcopyaddr: copy an IPv4 or IPv6 address  
 */
void IP_COPYADDR (ipaddr *toaddr, ipaddr fromaddr)
{
    if (ADDR_ISV6(&fromaddr)) {
	memcpy(&fromaddr.un.ip6.s6_addr,&toaddr->un.ip6, AF_INET6);
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
    if (ADDR_ISV6(&addr1)) {
	if (ADDR_ISV6(&addr2))
	    return (memcmp(addr1.un.ip6.s6_addr,
			   addr2.un.ip6.s6_addr,AF_INET6) == 0);
    } else {
	if (ADDR_ISV4(&addr2))
	    return (addr1.un.ip4.s_addr == addr2.un.ip4.s_addr);
    }
    return 0;	/* different types */
}



#ifdef IPV6NOTFOUND
/*
 * inet_ntop: makes a string address of the 16 byte ipv6 address
 */
const char *inet_ntop(int af, const char *src, char *dst, size_t size)
{
    int i;
    u_short s;
    char *temp;

    temp = dst;
    for (i = 0; i < AF_INET6; i++)
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
#endif


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
    memcpy(&addr.un.ip6.s6_addr,&addr6->s6_addr, AF_INET6);

    return(&addr);
}
