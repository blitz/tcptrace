/* 
 * snoop.c - SNOOP specific file reading stuff
 * 
 * Author:	Shawn Ostermann
 * 		Computer Science Department
 * 		Ohio University
 * Date:	Tue Nov  1, 1994
 *
 * Copyright (c) 1994 Shawn Ostermann
 */

#ifdef GROK_SNOOP

#include "tcptrace.h"


/* information necessary to understand Solaris Snoop output */
#define SNOOP_DUMP_OFFSET 16
struct snoop_packet_header {
    unsigned int	tlen;
    unsigned int	len;
    unsigned int	unused2;
    unsigned int	unused3;
    unsigned int	secs;
    unsigned int	usecs;
};


/* return the next packet header */
static int
pread_snoop(
    struct timeval	*ptime,
    int		 	*plen,
    struct ether_header **ppep,
    struct ip		**ppip)
{
    int packlen;
    int rlen;
    int len;
    struct snoop_packet_header hdr;
    static struct ether_header ep;
    static int ip_buf[IP_MAXPACKET/sizeof(int)];  /* force alignment */
    int hlen;


    hlen = sizeof(struct snoop_packet_header);

    /* read the packet header */
    if ((rlen=fread(&hdr,1,hlen,stdin)) != hlen) {
	if (rlen != 0)
	    fprintf(stderr,"Bad snoop packet header\n");
	return(0);
    }

    packlen = hdr.len;
    /* round up to multiple of 4 bytes */
    len = (packlen + 3) & ~0x3;

    /* read the ethernet header */
    rlen=fread(&ep,1,sizeof(struct ether_header),stdin);
    if (rlen != sizeof(struct ether_header)) {
	fprintf(stderr,"Couldn't read ether header\n");
	return(0);
    }

    /* read the rest of the packet */
    len -= sizeof(struct ether_header);
    if ((rlen=fread(ip_buf,1,len,stdin)) != len) {
	if (rlen != 0)
	    fprintf(stderr,"Couldn't read %d bytes\n", len);
	return(0);
    }

    ptime->tv_sec  = hdr.secs;
    ptime->tv_usec = hdr.usecs;
    *plen          = hdr.len;


    *ppip  = (struct ip *) ip_buf;
    *ppep  = &ep;

    return(1);
}



/*
 * is_snoop()   is the input file in snoop format??
 */
int (*is_snoop())()
{
    char buf[20];
    int rlen;

    /* read the snoop file header */
    if ((rlen=fread(buf,1,5,stdin)) != 5) {
	rewind(stdin);
	return(NULL);
    }
    rewind(stdin);

    if (strncmp(buf,"snoop",5) != 0)
	return(NULL);

    /* OK, it's a snoop file */

    /* ignore the header at the top */
    if (fseek(stdin,SNOOP_DUMP_OFFSET,SEEK_SET) == -1) {
	perror("lseek");
	exit(-1);
    }

    return(pread_snoop);
}
#endif GROK_SNOOP



