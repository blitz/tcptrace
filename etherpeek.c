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
  

#include "tcptrace.h"


#ifdef GROK_ETHERPEEK


/* NOTE:  This is for version 5 of the file.  Other file formats may not work
 correctly.*/

static struct EPFileHeader {
    char version;		/* file version (must be 5, 6, or 7)*/
    char status;		/* filler to fill to even boundary*/
} file_header;

static struct EPFileHeader2 {
    u_long length;		/* length of file*/
    u_long numPackets;		/* number of packets contained in the file*/
    u_long timeDate;		/* time and date stamp of the file (MAC format)*/
    u_long timeStart;		/* time of the first packet in the file*/
    u_long timeStop;		/* time of the last packet in the file*/
    u_long futureUse[7];	/*reserved for future use and irrelevent to us!*/
} file_header2;



struct EPFilePacket_v5_6 {
    u_short packetlength;	/* total packet length */
    u_short slicelength;	/* sliced length of packet*/
};

struct EPFilePacket2_v5_6 {
    u_char flags;		/* crc, frame, runt, ...*/
    u_char status;		/* slice, trunc, ...*/
};

struct EPFilePacket3_v5_6 { 
    u_long  timestamp;		/* timestamp in milliseconds*/
    short destNum;		/* str corresponding to ether address*/
    short srcNum;		/* dnum is entry in table*/
    short protoNum;		/* table number for the protocol*/
    char protoStr[8];		/* protocol identity string (NOT null terminated!)*/
    u_short filterNum;		/* index to filter table*/
};


/* what we need for version 7 */
typedef struct PeekPacket_v7 {
    u_short	protospec;	/* ProtoSpec ID. */
    u_short	packetlength;	/* Total length of packet. */
    u_short	slicelength;	/* Sliced length of packet. */
    u_char	flags;		/* CRC, frame, runt, ... */
    u_char	status;		/* Slicing, ... */
    u_long	timestamphi;	/* 64-bit timestamp in microseconds. */
    u_long	timestamplo;
} PeekPacket_v7;

/* byte swapping */
/* Mac's are in network byte order.  If this machine is NOT, then */
/* we'll need to do conversion */

  
static u_long mactime;

#define Real_Size_FH 2
#define Real_Size_FH2 48 
#define Real_Size_FP 4
#define Real_Size_FP2 2
#define Real_Size_FP3 20 

#define Mac2unix 2082844800u  /* difference between Unix and Mac timestamp */

#define VERSION_7 7    /* Version 7 */
#define VERSION_6 6    /* Version 6 */
#define VERSION_5 5    /* Version 5 */ 
static char thisfile_ep_version;
#define EP_V5 (thisfile_ep_version == VERSION_5)
#define EP_V6 (thisfile_ep_version == VERSION_6)
#define EP_V7 (thisfile_ep_version == VERSION_7)



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
    int len;

    /* read the EP packet header */
    while(1){
	if (EP_V5 || EP_V6) {
	    struct EPFilePacket_v5_6 hdr;
	    struct EPFilePacket2_v5_6 hdr2;
	    struct EPFilePacket3_v5_6 hdr3;

	    if ((rlen=fread(&hdr,1,Real_Size_FP,stdin)) != Real_Size_FP) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP header\n");
		return(0);
	    }
	    hdr.packetlength = ntohs(hdr.packetlength);
	    hdr.slicelength = ntohs(hdr.slicelength);

	    if (debug>1) {
		printf("EP_read: next packet: original length: %d, saved length: %d\n",
		       hdr.packetlength, hdr.slicelength);
	    }
	    
	
	    if ((rlen=fread(&hdr2,1,Real_Size_FP2,stdin)) !=Real_Size_FP2) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP header\n");
		return(0);
	    }

	    if ((rlen=fread(&hdr3,1,Real_Size_FP3,stdin)) != Real_Size_FP3) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP header\n");
		return(0);
	    }

	    if (hdr.slicelength)
		packlen = hdr.slicelength; 
	    else
		packlen = hdr.packetlength;

	    hdr3.timestamp = ntohl(hdr3.timestamp);
     
	    ptime->tv_sec  = mactime + (hdr3.timestamp / 1000); /*milliseconds div 1000*/
	    ptime->tv_usec = 1000 * (hdr3.timestamp % 1000);

	    *plen          = hdr.packetlength;
	    /* hmmm... I guess 0 bytes means that they grabbed the whole */
	    /* packet.  Seems to work that way... sdo - Thu Feb 13, 1997 */
	    if (hdr.slicelength)
		*ptlen = hdr.slicelength;
	    else
		*ptlen = hdr.packetlength;
	} else { /* version 7 */
	    struct PeekPacket_v7 hdrv7;

	    if ((rlen=fread(&hdrv7,sizeof(hdrv7),1,stdin)) != 1) {
		if (rlen != 0)
		    fprintf(stderr,"Bad EP V7 header (rlen is %d)\n", rlen);
		return(0);
	    }

	    hdrv7.packetlength = ntohs(hdrv7.packetlength);
	    hdrv7.slicelength = ntohs(hdrv7.slicelength);

	    if (hdrv7.slicelength)
		packlen = hdrv7.slicelength; 
	    else
		packlen = hdrv7.packetlength;

	    /* file save version 7 time is NOT an offset, it's a 64 bit counter in microseconds */
#ifdef HAVE_LONG_LONG
	    {  /* not everybody has LONG LONG now */
		unsigned long long int usecs;

		/* avoid ugly alignment problems */
		memcpy(&usecs, &hdrv7.timestamphi, sizeof(usecs));

		ptime->tv_sec  = usecs / 1000000 - Mac2unix;
		ptime->tv_usec = usecs % 1000000;

		if (0)
		    printf("hi: %lu  lo: %lu usecs: %lld  tv_sec: %lu  tv_usec: %06lu\n",
			   (u_long)hdrv7.timestamphi, (u_long)hdrv7.timestamplo,
			   usecs, ptime->tv_sec, ptime->tv_usec);
	    }
#else /* HAVE_LONG_LONG */
	    {
		double usecs;

		/* secs is hard because I don't want to depend on "long long" */
		/* which isn't universal yet.  "float" probably isn't enough */
		/* signigicant figures to make this work, so I'll do it in */
		/* (slow) double precision :-(  */
		usecs = (double)hdrv7.timestamphi * (65536.0 * 65536.0);
		usecs += (double)hdrv7.timestamplo;
		usecs -= (double)Mac2unix*1000000.0;
		ptime->tv_sec  = usecs/1000000.0;

		/* usecs is easier, the part we want is all in the lower word */
		ptime->tv_usec = usecs - (double)ptime->tv_sec * 1000000.0;

		if (0)
		    printf("hi: %lu  lo: %lu usecs: %f  tv_sec: %lu  tv_usec: %06lu\n",
			   (u_long)hdrv7.timestamphi, (u_long)hdrv7.timestamplo,
			   usecs, ptime->tv_sec, ptime->tv_usec);
	    }
#endif /* HAVE_LONG_LONG */


	    *plen          = hdrv7.packetlength;
	    /* hmmm... I guess 0 bytes means that they grabbed the whole */
	    /* packet.  Seems to work that way... sdo - Thu Feb 13, 1997 */
	    if (hdrv7.slicelength)
		*ptlen = hdrv7.slicelength;
	    else
		*ptlen = hdrv7.packetlength;

	    if (debug>1) {
		printf("File position: %ld\n", ftell(stdin));
		printf("pread_EP (v7) next packet:\n");
		printf("  packetlength: %d\n", hdrv7.packetlength);
		printf("  slicelength:  %d\n", hdrv7.slicelength);
		printf("  packlen:      %d\n", packlen);
		printf("  time:         %s\n", ts2ascii_date(ptime));
	    }
	}


	len= packlen;

	/* read the ethernet header */
	rlen=fread(pep,1,sizeof(struct ether_header),stdin);
	if (rlen != sizeof(struct ether_header)) {
	    fprintf(stderr,"Couldn't read ether header\n");
	    return(0);
	}


	if (debug > 3) {
	    PrintRawDataHex("EP_READ: Ethernet Dump", pep, (char *)(pep+1)-1);
	}

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
	if (EP_V7) {
	    if (len%2 != 0)
		fseek(stdin,1,SEEK_CUR);
	}

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
    int rlen;


    /* read the EP file header */
    if ((rlen=fread(&file_header,1,Real_Size_FH,stdin)) != Real_Size_FH) {
	rewind(stdin);
	return(NULL);
    }
    /*rewind(stdin);  I might need this*/
    if ((rlen=fread(&file_header2,1,Real_Size_FH2,stdin)) != Real_Size_FH2) {
	rewind(stdin);
	return(NULL);
    }

    /* byte swapping */
    file_header2.length = ntohl(file_header2.length);
    file_header2.numPackets = ntohl(file_header2.numPackets);
    file_header2.timeDate = ntohl(file_header2.timeDate);
    file_header2.timeStart = ntohl(file_header2.timeStart);
    file_header2.timeStop = ntohl(file_header2.timeStop);
    
    mactime=file_header2.timeDate - Mac2unix;  /*get time plus offset to unix time */
    /********** File header info ********************************/
    if (debug>1) {
	int i;
      
	printf("IS_EP says version number %d \n",file_header.version);
	printf("IS_EP says status number %d\n",file_header.status);
	printf("IS_EP says length number %ld\n",file_header2.length);
	printf("IS_EP says num packets number %ld \n",file_header2.numPackets);
	printf("IS_EP says time date in mac format %lu \n", (u_long)file_header2.timeDate);
	printf("IS_EP says time start  %lu \n",file_header2.timeStart);
	printf("IS_EP says time stop %lu \n",file_header2.timeStop);
	printf("future is: ");
	for(i=0;i<7;i++)
	    printf(" %ld ",file_header2.futureUse[i]);
	printf("\n");
	printf("RLEN is %d \n",rlen);
    }


    /* check for EP file format */
    /* Note, there's no "magic number" here, so this is just a heuristic :-( */
    if ((file_header.version == VERSION_7 ||
	 file_header.version == VERSION_6 ||
	 file_header.version == VERSION_5) &&
	(file_header.status == 0) &&
	(memcmp(file_header2.futureUse,"\000\000\000\000\000\000\000",7) == 0)) {
	if (debug)
	    printf("Valid Etherpeek format file (file version: %d)\n",
		   file_header.version);
	thisfile_ep_version = file_header.version;

    } else {
	if (debug)
	    fprintf(stderr,"I don't think this is version 5, 6, or 7 Ether Peek File\n");

	return(NULL);
    } 

    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_EP);
}

#endif /* GROK_ETHERPEEK */
