/* 
 * netm.c - NetMetrix specific file reading stuff
 * 
 * Author:	Shawn Ostermann
 * 		Dept. of Computer Sciences
 * 		Purdue University
 * Date:	Fri Sep  4 13:35:42 1992
 *
 * Copyright (c) 1992 Shawn Ostermann
 */

#include "tcptrace.h"
#include "netm.h"


int netm_oldversion;

int
is_netm()
{
	struct netm_header nhdr;
	int rlen;

	/* read the netm file header */
	if ((rlen=fread(&nhdr,1,sizeof(nhdr),stdin)) != sizeof(nhdr)) {
		rewind(stdin);
		return(0);
	}
	rewind(stdin);

	/* check for NETM */
	if (nhdr.netm_key != NETM_KEY) {
		return(0);
	}


	/* check version */
	if (nhdr.version == VERSION_OLD)
	    netm_oldversion = 1;
	else if (nhdr.version == VERSION_NEW)
	    netm_oldversion = 0;
	else {
		fprintf(stderr,"Bad NETM file header version: %d\n",
			nhdr.version);
		return(0);
	}

	if (debug)
	    printf("NETM file version: %d\n", nhdr.version);

	/* ignore the header at the top */
	if (fseek(stdin,NETM_DUMP_OFFSET,SEEK_SET) == -1) {
		perror("NETM lseek");
		exit(-1);
	}

	return(1);
}



int
pread_netm(ptime,plen,ppep,ppip)
     struct timeval	 *ptime;
     int		 *plen;
     struct ether_header **ppep;
     struct ip		 **ppip;
{
	int packlen;
	int rlen;
	int len;
	struct packet_header hdr;
	static char ebuf[32];
	static char buf[2000];
	int hlen;


	hlen = netm_oldversion?
	    (sizeof(struct packet_header_old)):
		(sizeof(struct packet_header));

	/* read the netm packet header */
	if ((rlen=fread(&hdr,1,hlen,stdin)) != hlen) {
		if (rlen != 0)
		    fprintf(stderr,"Bad netm header\n");
		return(0);
	}

	packlen = hdr.tlen;
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

	if (netm_oldversion) {
		struct packet_header_old *pho;
		pho = (struct packet_header_old *) &hdr;

		ptime->tv_sec  = pho->tstamp_secs;
		ptime->tv_usec = pho->tstamp_usecs;
		*plen          = pho->len;
	} else {
		ptime->tv_sec = hdr.tstamp_secs;
		ptime->tv_usec = hdr.tstamp_usecs;
		*plen = hdr.len;
	}


	*ppip  = (struct ip *) buf;
	*ppep  = (struct ether_header *) ebuf;

	return(1);
}
