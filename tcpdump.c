/*
 * Copyright (c) 1994, 1995, 1996, 1997
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

#include <stdio.h>
#include "tcptrace.h"

#ifdef GROK_TCPDUMP

#include "tcpdump.h"



/* local globals */
static struct ether_header *pep_buf;
static struct ip *pip_buf;
static struct dump_file_header dfh;


/* return the next packet header */
/* currently only works for ETHERNET and FDDI */
static int
pread_tcpdump(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip)
{
    struct packet_header hdr;
    int rlen;
    int iplen;
    int type;

    while (1) {  /* loop until we find an IP packet */
	/* read the packet header */
	if ((rlen=fread(&hdr,sizeof(hdr),1,stdin)) != 1) {
	    if (rlen != 0)
		fprintf(stderr,"Bad tcpdump packet header\n");
	    return(0);
	}

	/* convert the packet header to local byte order */
	if (tcpdump_doswap)
	    swap_phdr(&hdr);

	/* how much data is there? */
	iplen = hdr.caplen;  /* less frame header, subracted below */


	type = dfh.linktype;

	if (debug > 1)
	    printf("tcpdump_read: read from type %d (%s)\n",
		   type,
		   (type==DLT_EN10MB)?"Ethernet10":
		   (type==DLT_SLIP)?"SLIP":
		   (type==DLT_FDDI)?"FDDI":
		   "<unknown>");

	switch (type) {
	  case DLT_EN10MB:
	    /* read the ethernet header */
	    if ((rlen=fread(pep_buf,sizeof(struct ether_header),1,stdin))
		!= 1) {
		if (rlen != 0)
		    fprintf(stderr,"Bad tcpdump ethernet header (rlen %d)\n",
			    rlen);
		return(0);
	    }
	    if (ntohs(pep_buf->ether_type) != ETHERTYPE_IP) {
		if (debug>1)
		    printf("tcpdump_read: skipping non ETHER/IP packet\n");
		/* throw away the rest */
		fseek(stdin,iplen-sizeof(struct ether_header), SEEK_CUR);
		continue;
	    }
	    *pphys  = pep_buf;
	    iplen -= sizeof(struct ether_header);
	    *pphystype = PHYS_ETHER;
	    break;
	  case DLT_SLIP:
	    /* don't care about the 16 byte header */
	    if (fseek(stdin,16,SEEK_CUR) != 0) {
		perror("fseek");
		fprintf(stderr,"tcpdump_SLIP: bad seek\n");
		exit(-1);
	    }
	    *pphys  = NULL;
	    *pphystype = PHYS_ETHER;  /* lie a little */
	    break;
	  case DLT_FDDI:
	    *pphys  = NULL;
	    *pphystype = PHYS_FDDI;  /* lie a little */
	    break;
	  default:
	    if (debug>1)
		printf("tcpdump_read: unknown phys frame type %d (%s)\n",
		       type,
		       (type==DLT_EN10MB)?"Ethernet10":
		       (type==DLT_SLIP)?"SLIP":
		       (type==DLT_FDDI)?"FDDI":
		       "<unknown>");
	    exit(-1);
	}

	/* read the IP portion of the packet */
	if ((rlen=fread(pip_buf,iplen,1,stdin)) != 1) {
	    if (rlen != 0)
		fprintf(stderr,"Bad tcpdump IP packet (rlen %d)\n",
			rlen);
	    return(0);
	}

	ptime->tv_sec  = hdr.ts_secs;
	ptime->tv_usec = hdr.ts_usecs;
	*plen          = hdr.len;
	*ptlen         = hdr.caplen;

	*ppip  = (struct ip *) pip_buf;

	/* if it's not TCP/IP, then skip it */
	if ((*ppip)->ip_p != IPPROTO_TCP) {
	    if (debug>1)
		printf("tcpdump_read: skipping non TCP packet\n");
	    continue;
	}
	break;
    }

    if (debug>2)
	printf("tcpdump_read: returning packet\n");

    return(1);
}



int (*is_tcpdump(void))()
{
    int rlen;

    if (debug)
	printf("Using 'fread' version of tcpdump\n");

    /* read the file header */
    if ((rlen=fread(&dfh,sizeof(dfh),1,stdin)) != 1) {
	rewind(stdin);
	return(NULL);
    }

    if (dfh.magic == TCPDUMP_MAGIC) {
	if (debug>1)
	    printf("tcpdump_mmap: saw magic number (native byte order)\n");
	tcpdump_doswap = FALSE;
    } else if (SWAPLONG(dfh.magic) == TCPDUMP_MAGIC) {
	if (debug>1)
	    printf("tcpdump_mmap: saw magic number (reverse byte order)\n");
	tcpdump_doswap = TRUE;
    } else {
	/* not a tcpdump file */
	rewind(stdin);
	return(NULL);
    }

    if (tcpdump_doswap)
	swap_hdr(&dfh);

    if (debug) {
	printf("This is a tcpdump file, header says:\n");
	printf("\t version  %d.%d\n", dfh.version_major, dfh.version_minor);
	printf("\t snaplen  %d\n", dfh.snaplen);
	printf("\t linktype %d\n", dfh.linktype);
    }
    linktype = dfh.linktype;
    snaplen = dfh.snaplen;

    /* OK, it's mine.  Init some stuff */
    pep_buf = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    
    return(pread_tcpdump);
}


#endif /* GROK_TCPDUMP */
