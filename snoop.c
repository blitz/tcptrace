/* 
 * snoop.c - SNOOP specific file reading stuff
 * 
 * Author:	Shawn Ostermann
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Fri Sep  4 13:35:42 1992
 *
 * Copyright (c) 1992 Shawn Ostermann
 */

#include "tcptrace.h"
#include "snoop.h"



int
is_snoop()
{
	char buf[20];
	int rlen;

	/* read the netm file header */
	if ((rlen=fread(buf,1,5,stdin)) != 5) {
		rewind(stdin);
		return(0);
	}
	rewind(stdin);

	if (strncmp(buf,"snoop",5) != 0)
	    return(0);

	/* OK, it's a snoop file */

	/* ignore the header at the top */
	if (fseek(stdin,SNOOP_DUMP_OFFSET,SEEK_SET) == -1) {
		perror("lseek");
		exit(-1);
	}

	return(1);
}



int
pread_snoop(ptime,plen,ppep,ppip)
     struct timeval	 *ptime;
     int		 *plen;
     struct ether_header **ppep;
     struct ip		 **ppip;
{
	int packlen;
	int rlen;
	int len;
	struct snoop_packet_header hdr;
	static char ebuf[32];
	static char buf[2000];
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
	rlen=fread(ebuf,1,sizeof(struct ether_header),stdin);
	if (rlen != sizeof(struct ether_header)) {
		fprintf(stderr,"Couldn't read ether header\n");
		return(0);
	}

	/* read the rest of the packet */
	len -= sizeof(struct ether_header);
	if ((rlen=fread(buf,1,len,stdin)) != len) {
		if (rlen != 0)
		    fprintf(stderr,"Couldn't read %d bytes\n", len);
		return(0);
	}

	ptime->tv_sec  = hdr.secs;
	ptime->tv_usec = hdr.usecs;
	*plen          = hdr.len;


	*ppip  = (struct ip *) buf;
	*ppep  = (struct ether_header *) ebuf;

	return(1);
}
