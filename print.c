/* 
 * print.c -- packet printing routines
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#include "tcptrace.h"


/* local routines */



char *
ts(
    struct timeval	*ptime)
{
	static char buf[100];
	struct tm *ptm;
	char *now;
	int decimal;

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);
	now[19] = '\00';

	decimal = (ptime->tv_usec + 50) / 100;
	sprintf(buf, "%s.%04d", now, decimal);

	return(buf);
}


void
printeth(
    struct ether_header *pep)
{
    printf("\tETH From: %s\n", ether_ntoa(pep->ether_shost));
    printf("\t    Dest: %s\n", ether_ntoa(pep->ether_dhost));

    printf(
	hex?"\t    Type: 0x%x %s\n":"\t    Type: %d %s\n",
	pep->ether_type,
	(pep->ether_type == ETHERTYPE_IP)?"(IP)":
	(pep->ether_type == ETHERTYPE_ARP)?"(ARP)":
	"");
}


void
printip(
    struct ip *pip)
{
    printf("\tIP From: %s\n", inet_ntoa(pip->ip_src));
    printf("\t   Dest: %s\n", inet_ntoa(pip->ip_dst));

    printf("\t     ID: %d\n", ntohs(pip->ip_id));

    printf(
	hex?"\t   Type: 0x%x %s\n":"\t   Type: %d %s\n",
	ntohs(pip->ip_p), 
	(ntohs(pip->ip_p) == IPPROTO_UDP)?"(UDP)":
	(ntohs(pip->ip_p) == IPPROTO_TCP)?"(TCP)":
	"");
}


void
printtcp(
    struct ip *pip)
{
    unsigned tcp_length;
    unsigned tcp_data_length;
    struct tcphdr *ptcp;

    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);

    /* calculate data length */
    tcp_length = ntohs(pip->ip_len) - (4 * pip->ip_hl);
    tcp_data_length = tcp_length - (4 * ptcp->th_off);

    printf("\tTCP SPORT: %u\n", ntohs(ptcp->th_sport));
    printf("\t    DPORT: %u\n", ntohs(ptcp->th_dport));
    printf("\t    FLG:   %c%c%c%c%c%c\n",
	   URGENT_SET(ptcp)?'U':'-',
	   ACK_SET(ptcp)?   'A':'-',
	   PUSH_SET(ptcp)?  'P':'-',
	   RESET_SET(ptcp)? 'R':'-',
	   SYN_SET(ptcp)?   'S':'-',
	   FIN_SET(ptcp)?   'F':'-');
    printf(
	hex?"\t    SEQ:   0x%08x\n":"\t    SEQ:   %d\n",
	ntohl(ptcp->th_seq));
    printf(
	hex?"\t    ACK:   0x%08x\n":"\t    ACK:   %d\n",
	ntohl(ptcp->th_ack));
    printf("\t    WIN:   %u\n", ntohs(ptcp->th_win));
    if (ptcp->th_off != 5)
        printf("\tHDR LEN:   %u\n", ptcp->th_off*4);
    if (tcp_data_length > 0)
	printf("\t   data:   %u bytes\n", tcp_data_length);
}



void
printpacket(
     struct timeval	time,
     int		len,
     int		tlen,
     struct ether_header *pep,
     struct ip		*pip)
{
    if (len == tlen)
        printf("\tPacket Length: %d\n", len);
    else
        printf("\tPacket Length: %d (saved length %d)\n", len,tlen);

    printf("\tCollected: %s\n", ts(&time));

    printeth(pep);

    if (pep->ether_type != ETHERTYPE_IP)
	return;
    printip(pip);

    if (ntohs(pip->ip_p) != IPPROTO_TCP)
	return;
    printtcp(pip);
}
