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
 * print.c -- packet printing routines
 */

#include "tcptrace.h"


/* local routines */
static void printeth_packet(struct ether_header *);
static void printip_packet(struct ip *, void *plast);
static void printtcp_packet(struct ip *, void *plast);
static char *ParenServiceName(portnum);
static char *ParenHostName(ipaddr);



/* Unix format: "Fri Sep 13 00:00:00 1986\n" */
char *
ts2ascii(
    struct timeval	*ptime)
{
	static char buf[30];
	struct tm *ptm;
	char *now;
	int decimal;

	if (ZERO_TIME(ptime))
	    return("        <the epoch>       ");

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);
	now[19] = '\00';

/* 	decimal = (ptime->tv_usec + 50) / 100;*/  /* for 4 digits */
	decimal = ptime->tv_usec;  /* for 6 digits */
	sprintf(buf, "%s.%06d", now, decimal);

	return(buf);
}


static void
printeth_packet(
    struct ether_header *pep)
{
    printf("\tETH Srce: %s\n", ether_ntoa((struct ether_addr *)&pep->ether_shost));
    printf("\t    Dest: %s\n", ether_ntoa((struct ether_addr *)&pep->ether_dhost));

    printf(
	hex?"\t    Type: 0x%x %s\n":"\t    Type: %d %s\n",
	pep->ether_type,
	(pep->ether_type == ETHERTYPE_IP)?"(IP)":
	(pep->ether_type == ETHERTYPE_ARP)?"(ARP)":
	(pep->ether_type == ETHERTYPE_REVARP)?"(RARP)":
	"");
}


static void
printip_packet(
    struct ip *pip,
    void *plast)
{
    /* make sure we have enough of the packet */
    if ((unsigned)pip+sizeof(struct ip)-1 > (unsigned)plast) {
	if (printtrunc)
	    printf("\t[packet truncated too short for IP details]\n");
	++ctrunc;
	return;
    }

    printf("\tIP  Srce: %s %s\n",
	   inet_ntoa(pip->ip_src),
	   ParenHostName(pip->ip_src));
    printf("\t    Dest: %s %s\n",
	   inet_ntoa(pip->ip_dst),
	   ParenHostName(pip->ip_dst));

    printf(
	hex?"\t    Type: 0x%x %s\n":"\t    Type: %d %s\n",
	ntohs(pip->ip_p), 
	(ntohs(pip->ip_p) == IPPROTO_UDP)?"(UDP)":
	(ntohs(pip->ip_p) == IPPROTO_TCP)?"(TCP)":
	(ntohs(pip->ip_p) == IPPROTO_ICMP)?"(ICMP)":
	(ntohs(pip->ip_p) == IPPROTO_IGMP)?"(IGMP)":
	(ntohs(pip->ip_p) == IPPROTO_EGP)?"(EGP)":
	"");

    printf("\t    HLEN: %d\n", pip->ip_hl*4);
    printf("\t     TTL: %d\n", pip->ip_ttl);
    printf("\t     LEN: %d\n", ntohs(pip->ip_len));
    printf("\t      ID: %d\n", ntohs(pip->ip_id));
}



static void
printtcp_packet(
    struct ip *pip,
    void *plast)
{
    unsigned tcp_length;
    unsigned tcp_data_length;
    struct tcphdr *ptcp;
    u_char *pdata;

    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);

    /* make sure we have enough of the packet */
    if ((unsigned)ptcp+sizeof(struct tcphdr)-1 > (unsigned)plast) {
	if (printtrunc)
	    printf("\t[packet truncated too short for TCP details]\n");
	++ctrunc;
	return;
    }

    /* calculate data length */
    tcp_length = ntohs(pip->ip_len) - (4 * pip->ip_hl);
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    printf("\tTCP SPRT: %u %s\n",
	   ntohs(ptcp->th_sport),
	   ParenServiceName(ntohs(ptcp->th_sport)));
    printf("\t    DPRT: %u %s\n",
	   ntohs(ptcp->th_dport),
	   ParenServiceName(ntohs(ptcp->th_dport)));
    printf("\t     FLG: %c%c%c%c%c%c\n",
	   URGENT_SET(ptcp)?'U':'-',
	   ACK_SET(ptcp)?   'A':'-',
	   PUSH_SET(ptcp)?  'P':'-',
	   RESET_SET(ptcp)? 'R':'-',
	   SYN_SET(ptcp)?   'S':'-',
	   FIN_SET(ptcp)?   'F':'-');
    printf(
	hex?"\t     SEQ: 0x%08x\n":"\t     SEQ: %d\n",
	ntohl(ptcp->th_seq));
    printf(
	hex?"\t     ACK: 0x%08x\n":"\t     ACK: %d\n",
	ntohl(ptcp->th_ack));
    printf("\t     WIN: %u\n", ntohs(ptcp->th_win));
    printf("\t    HLEN: %u\n", ptcp->th_off*4);
    pdata = (u_char *)ptcp + ptcp->th_off*4;
    printf("\t    DLEN: %u",
	   tcp_data_length);
    if ((u_long)pdata + tcp_data_length > ((u_long)plast+1))
	printf(" (only %ld bytes in dump file)\n",
	       (u_long)plast - (u_long)pdata + 1);
    printf("\n");
    if (ptcp->th_off != 5) {
	struct tcp_options *ptcpo;

        printf("\t    OPTS: %u bytes\t",
	       (ptcp->th_off*4) - sizeof(struct tcphdr));

	ptcpo = ParseOptions(ptcp,plast);

	if (ptcpo->mss != -1)
	    printf(" MSS(%d)", ptcpo->mss);
	if (ptcpo->ws != -1)
	    printf(" WS(%d)", ptcpo->ws);
	if (ptcpo->tsval != -1) {
	    printf(" TS(%ld,%ld)", ptcpo->tsval, ptcpo->tsecr);
	}
	if (ptcpo->sack_req) {
	    printf(" SACKREQ");
	}
	if (ptcpo->sack_count >= 0) {
	    int i;
	    printf(" SACKS(%d)", ptcpo->sack_count);
	    for (i=0; i < ptcpo->sack_count; ++i) {
		printf("[0x%08lx-0x%08lx]",
		       ptcpo->sacks[i].sack_left,
		       ptcpo->sacks[i].sack_right);
	    }
	}
        printf("\n");
    }
    if (tcp_data_length > 0)
	printf("\t    data: %u bytes\n", tcp_data_length);
}



void
printpacket(
     int		len,
     int		tlen,
     void		*phys,
     int		phystype,
     struct ip		*pip,
     void 		*plast)
{
    if (len == tlen)
        printf("\tPacket Length: %d\n", len);
    else
        printf("\tPacket Length: %d (saved length %d)\n", len,tlen);

    printf("\tCollected: %s\n", ts2ascii(&current_time));

    switch(phystype) {
      case PHYS_ETHER:
	printeth_packet(phys);
	break;
      default:
	printf("\tPhysical layer: %d (not understood)\n", phystype);
	break;
    }


    /* it's always supposed to be an IP packet */
    printip_packet(pip,plast);


    if (ntohs(pip->ip_p) == IPPROTO_TCP)
	printtcp_packet(pip,plast);
}


static char *
ParenServiceName(
     portnum port)
{
    char *pname;
    static char buf[80];

    pname = ServiceName(port);
    if (!pname || isdigit(*pname))
	return("");

    sprintf(buf,"(%s)",pname);
    return(buf);
}


static char *
ParenHostName(
     ipaddr addr)
{
    char *pname;
    static char buf[80];

    pname = HostName(addr);
    if (!pname || isdigit(*pname))
	return("");

    sprintf(buf,"(%s)",pname);
    return(buf);
}


void
PrintRawData(
    char *label,
    void *pfirst,
    void *plast)
{
    int lcount = 0;
    int count = (unsigned)plast - (unsigned)pfirst + 1;
    u_char *pch = pfirst;

    if (count <= 0)
	return;

    printf("========================================\n");
    printf("%s (%d bytes):\n\t", label, count);

    while (pch <= (u_char *) plast) {
	if ((*pch == '\r') && (*(pch+1) == '\n')) {
	    printf("\n\t");
	    ++pch;
	    lcount = 0;
	} else if (isprint(*pch)) {
	    putchar(*pch);
	    lcount+=1;
	} else {
	    printf("\\%03o", *pch);
	    lcount+=3;
	}
	if (lcount > 60) {
	    printf("\n\t");
	    lcount = 0;
	}
	++pch;
    }
    printf("\n");
}


