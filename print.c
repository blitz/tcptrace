/* 
 * print.c -- packet printing routines
 * 
 * Author:	Shawn Ostermann
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Fri Sep  4 13:35:42 1992
 *
 * Copyright (c) 1992 Shawn Ostermann
 */

#include "tcptrace.h"


/* local routines */
char *ts();
void printeth();
void printip();
void printtcp();
void printone();



char *
ts(ptime)
     struct timeval	*ptime;
{
	static char buf[100];
	struct tm *ptm;
	char *now;

	ptm = localtime(&ptime->tv_sec);
	now = asctime(ptm);
	now[19] = '\00';

	sprintf(buf, "%s.%03d", now, ptime->tv_usec / 1000);

	return(buf);
}


void
printeth(pep)
     struct ether_header *pep;
{
	printf("\tETH From: %s\n", ether_ntoa(pep->ether_shost));
	printf("\t    Dest: %s\n", ether_ntoa(pep->ether_dhost));

	printf("\t    Type: 0x%x %s\n",
	       pep->ether_type,
	       (pep->ether_type == ETHERTYPE_IP)?"(IP)":
	       (pep->ether_type == ETHERTYPE_ARP)?"(ARP)":
	       "");
}


void
printip(pip)
     struct ip *pip;
{
	printf("\tIP From: %s\n", inet_ntoa(pip->ip_src));
	printf("\t   Dest: %s\n", inet_ntoa(pip->ip_dst));

	printf("\t   Type: 0x%x %s\n",
	       ntohs(pip->ip_p), 
	       (ntohs(pip->ip_p) == IPPROTO_UDP)?"(UDP)":
	       (ntohs(pip->ip_p) == IPPROTO_TCP)?"(TCP)":
	       "");
}


void
printtcp(pip)
     struct ip *pip;
{
	struct tcphdr *ptcp;

	ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);

	printf("\tTCP SPORT: %u\n", ntohs(ptcp->th_sport));
	printf("\t    DPORT: %u\n", ntohs(ptcp->th_dport));
	printf("\t    FLG:   %c%c%c%c%c%c\n",
	       (ptcp->th_flags & TH_FIN)?'F':'-',
	       (ptcp->th_flags & TH_SYN)?'S':'-',
	       (ptcp->th_flags & TH_RST)?'R':'-',
	       (ptcp->th_flags & TH_PUSH)?'P':'-',
	       (ptcp->th_flags & TH_ACK)?'A':'-',
	       (ptcp->th_flags & TH_URG)?'U':'-');
	printf("\t    SEQ:   0x%08x\n", ntohl(ptcp->th_seq));
	printf("\t    ACK:   0x%08x\n", ntohl(ptcp->th_ack));
	printf("\t    WIN:   %u\n", ntohs(ptcp->th_win));
	printf("\t    OFF:   %u\n", ptcp->th_off);
}



void
printpacket(time,len,pep,pip)
     struct timeval	time;
     int		len;
     struct ether_header *pep;
     struct ip		*pip;
{
	printf("\tPacket Length: %d\n", len);

	printf("\tCollected: %s\n", ts(&time));

	printeth(pep);

	if (pep->ether_type != ETHERTYPE_IP)
	    return;
	printip(pip);

	if (ntohs(pip->ip_p) != IPPROTO_TCP)
	    return;
	printtcp(pip);
}
