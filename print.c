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
static void printeth_packet(struct ether_header *);
static void printip_packet(struct ip *);
static void printtcp_packet(struct ip *);
static char *ParenServiceName(portnum);
static char *ParenHostName(ipaddr);



char *
ts2ascii(
    struct timeval	*ptime)
{
	static char buf[30];
	struct tm *ptm;
	char *now;
	int decimal;

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
    printf("\tETH Srce: %s\n", ether_ntoa(pep->ether_shost));
    printf("\t    Dest: %s\n", ether_ntoa(pep->ether_dhost));

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
    struct ip *pip)
{
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

    printf("\t     TTL: %d\n", pip->ip_ttl);
    printf("\t     LEN: %d\n", ntohs(pip->ip_len));
    printf("\t      ID: %d\n", ntohs(pip->ip_id));
}



static void
printtcp_packet(
    struct ip *pip)
{
    unsigned tcp_length;
    unsigned tcp_data_length;
    struct tcphdr *ptcp;
    u_char *pdata;

    ptcp = (struct tcphdr *) ((char *)pip + 4*pip->ip_hl);

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
    pdata = (u_char *)ptcp + ptcp->th_off*4;
    if (ptcp->th_off != 5) {
	struct tcp_options *ptcpo;

        printf("\t    OPTS: %u bytes\t",
	       (ptcp->th_off*4) - sizeof(struct tcphdr));

	ptcpo = ParseOptions(ptcp);

	if (ptcpo->mss != -1)
	    printf(" MSS(%d)", ptcpo->mss);
	if (ptcpo->ws != -1)
	    printf(" WS(%d)", ptcpo->ws);
	if (ptcpo->tsval != -1) {
	    printf(" TS(%ld,%ld)", ptcpo->tsval, ptcpo->tsecr);
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
     struct ip		*pip)
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
    printip_packet(pip);


    if (ntohs(pip->ip_p) == IPPROTO_TCP)
	printtcp_packet(pip);
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


