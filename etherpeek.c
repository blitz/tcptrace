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
static char const copyright[] =
    "@(#)Copyright (c) 1996 -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


/****************************************
**  This is the Ether Peek reading stuff.
**  Author: Brian Wilson
**          Ohio University
**          Computer Science
**  Date:   Mon, July   ,1995
****************************************/
  

#include <stdio.h>
#include "tcptrace.h"


#ifdef GROK_ETHERPEEK


/* NOTE:  This is for version 5 of the file.  Other file formats may not work
 correctly.*/

static char ep_version;

struct EPFileHeader {
    char	version;	/* file version (must be 5, 6, or 7)*/
    char	status;		/* filler to fill to even boundary*/
};

struct EPFileHeader2 {
    unsigned long length;	/* length of file*/
    unsigned long numPackets;	/* number of packets contained in the file*/
    unsigned long timeDate;	/* time and date stamp of the file (MAC format)*/
    unsigned long timeStart;	/* time of the first packet in the file*/
    unsigned long timeStop;	/* time of the last packet in the file*/
    unsigned long futureUse[7];	/*reserved for future use and irrelevent to us!*/
};

struct EPFilePacket {
    unsigned short packetLength;/* total packet length */
    unsigned short sliceLength;	/* sliced length of packet*/
};

struct EPFilePacket2 {
    unsigned char flags;	/* crc, frame, runt, ...*/
    unsigned char status;	/* slice, trunc, ...*/
};

struct EPFilePacket3 { 
    unsigned long  timestamp;	/* timestamp in milliseconds*/
    short destNum;		/* str corresponding to ether address*/
    short srcNum;		/* dnum is entry in table*/
    short protoNum;		/* table number for the protocol*/
    char protoStr[8];		/* protocol identity string (NOT null terminated!)*/
    unsigned short filterNum;	/* index to filter table*/
};



/* byte swapping */
/* Mac's are in network byte order.  If this machine is NOT, then */
/* we'll need to do conversion */

  
unsigned long mactime;

#define Real_Size_FH 2
#define Real_Size_FH2 48 
#define Real_Size_FP 4
#define Real_Size_FP2 2
#define Real_Size_FP3 20 

#define Mac2unix 2082844800u  /* difference between Unix and Mac timestamp */

#define VERSION_7 7    /* Version 7 */
#define VERSION_6 6    /* Version 6 */
#define VERSION_5 5    /* Version 5 */ 


/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;


/* currently only works for ETHERNET */
static int
pread_EP(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int packlen;
    int rlen;
    struct EPFilePacket hdr;
    struct EPFilePacket2 hdr2;
    struct EPFilePacket3 hdr3;
    int len;

    /* read the EP packet header */
    while(1){
	if ((rlen=fread(&hdr,1,Real_Size_FP,stdin)) != Real_Size_FP) {
	    if (rlen != 0)
		fprintf(stderr,"Bad EP header\n");
	    return(0);
	}
	hdr.packetLength = ntohs(hdr.packetLength);
	hdr.sliceLength = ntohs(hdr.sliceLength);

	if (debug>1) {
	    printf("EP_read: next packet: original length: %d, saved length: %d\n",
		   hdr.packetLength, hdr.sliceLength);
	}
	    
	
	if ((rlen=fread(&hdr2,1,Real_Size_FP2,stdin)) !=Real_Size_FP2) {
	    if (rlen != 0)
		fprintf(stderr,"Bad EP header\n");
	    return(0);
	}
	if ((ep_version == VERSION_5) || (ep_version == VERSION_6)) {
	    if ((rlen=fread(&hdr3,1,Real_Size_FP3,stdin)) != Real_Size_FP3) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP header\n");
		return(0);
	    }
	} else {
	    /* only 10 bytes in version 7, I don't know the details */
	    if ((rlen=fread(&hdr3,10,1,stdin)) != 1) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP v7 header\n");
		return(0);
	    }
	}
	hdr3.timestamp = ntohl(hdr3.timestamp);

	if (hdr.sliceLength)
	    packlen = hdr.sliceLength; 
	else
	    packlen = hdr.packetLength;
     
	len= packlen;

	/* read the ethernet header */
	rlen=fread(pep,1,sizeof(struct ether_header),stdin);
	if (rlen != sizeof(struct ether_header)) {
	    fprintf(stderr,"Couldn't read ether header\n");
	    return(0);
	}


	if (debug > 3)
	    PrintRawDataHex("EP_READ: Ethernet Dump", pep, (char *)(pep+1)-1);

	/* read the rest of the packet */
	len -= sizeof(struct ether_header);
	if ((rlen=fread(pip_buf,1,len,stdin)) != len) {
	    if (rlen != 0)
		fprintf(stderr,
			"Couldn't read %d more bytes, skipping last packet\n",
			len);
	    return(0);
	}

	if (debug > 3)
	    PrintRawDataHex("EP_READ: IP Dump", pip_buf, (char *)pip_buf+len-1);

	/* round to 2 bytes for V7 */
	if (ep_version == VERSION_7) {
	    if (len%2 != 0)
		fseek(stdin,1,SEEK_CUR);
	}

	ptime->tv_sec  = mactime + (hdr3.timestamp / 1000); /*milliseconds div 1000*/
	ptime->tv_usec = 1000 * (hdr3.timestamp % 1000);
	*plen          = hdr.packetLength;
	/* hmmm... I guess 0 bytes means that they grabbed the whole */
	/* packet.  Seems to work that way... sdo - Thu Feb 13, 1997 */
	if (hdr.sliceLength)
	    *ptlen = hdr.sliceLength;
	else
	    *ptlen = hdr.packetLength;

	*ppip  = (struct ip *) pip_buf;
	*pplast = (char *)pip_buf+len-1; /* last byte in the IP packet */
	*pphys  = pep;
	*pphystype = PHYS_ETHER;

	/* if it's not TCP/IP, then skip it */
	if ((ntohs(pep->ether_type) != ETHERTYPE_IP) ||
	    ((*ppip)->ip_p != IPPROTO_TCP))
	    continue;

	return(1);
    }
}



/* is the input file a Ether Peek format file?? */
pread_f *is_EP(void)
{
    struct EPFileHeader nhdr;
    struct EPFileHeader2 nhdr2;
    int rlen;


    /* read the EP file header */
    if ((rlen=fread(&nhdr,1,Real_Size_FH,stdin)) != Real_Size_FH) {
	rewind(stdin);
	return(NULL);
    }
    /*rewind(stdin);  I might need this*/
    if ((rlen=fread(&nhdr2,1,Real_Size_FH2,stdin)) != Real_Size_FH2) {
	rewind(stdin);
	return(NULL);
    }

    /* byte swapping */
    nhdr2.length = ntohl(nhdr2.length);
    nhdr2.numPackets = ntohl(nhdr2.numPackets);
    nhdr2.timeDate = ntohl(nhdr2.timeDate);
    nhdr2.timeStart = ntohl(nhdr2.timeStart);
    nhdr2.timeStop = ntohl(nhdr2.timeStop);
    
    mactime=nhdr2.timeDate - Mac2unix;  /*get time plus offset to unix time */
    /********** File header info ********************************/
    if (debug>1) {
	int i;
      
	printf("IS_EP says version number %c %d \n",nhdr.version,nhdr.version);
	printf("IS_EP says status number %c %d\n",nhdr.status,nhdr.status);
	printf("IS_EP says length number %ld\n",nhdr2.length);
	printf("IS_EP says num packets number %ld \n",nhdr2.numPackets);
	printf("IS_EP says time date in mac format %ld \n",nhdr2.timeDate);
	printf("IS_EP says time start  %ld \n",nhdr2.timeStart);
	printf("IS_EP says time stop %ld \n",nhdr2.timeStop);
	printf("future is: ");
	for(i=0;i<7;i++)
	    printf(" %ld ",nhdr2.futureUse[i]);
	printf("\n");
	printf("RLEN is %d \n",rlen);
    }


    /* check for EP */
    if (nhdr.version != VERSION_7 &&
	nhdr.version != VERSION_6 &&
	nhdr.version != VERSION_5 ) {
	if (debug)
	    fprintf(stderr,"I don't think this is version 5, 6, or 7 Ether Peek File\n");

	return(NULL);
    } 

    if (debug)
	printf("EP file version: %d\n", nhdr.version);
    ep_version = nhdr.version;

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_EP);
}

#endif /* GROK_ETHERPEEK */
