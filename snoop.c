/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
 *	Ohio University.
 *
 * ---
 * 
 * Starting with the release of tcptrace version 6 in 2001, tcptrace
 * is licensed under the GNU General Public License (GPL).  We believe
 * that, among the available licenses, the GPL will do the best job of
 * allowing tcptrace to continue to be a valuable, freely-available
 * and well-maintained tool for the networking community.
 *
 * Previous versions of tcptrace were released under a license that
 * was much less restrictive with respect to how tcptrace could be
 * used in commercial products.  Because of this, I am willing to
 * consider alternate license arrangements as allowed in Section 10 of
 * the GNU GPL.  Before I would consider licensing tcptrace under an
 * alternate agreement with a particular individual or company,
 * however, I would have to be convinced that such an alternative
 * would be to the greater benefit of the networking community.
 * 
 * ---
 *
 * This file is part of Tcptrace.
 *
 * Tcptrace was originally written and continues to be maintained by
 * Shawn Ostermann with the help of a group of devoted students and
 * users (see the file 'THANKS').  The work on tcptrace has been made
 * possible over the years through the generous support of NASA GRC,
 * the National Science Foundation, and Sun Microsystems.
 *
 * Tcptrace is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tcptrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tcptrace (in the file 'COPYING'); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";


/* 
 * snoop.c - SNOOP specific file reading stuff
 *	ipv6 addition by Nasseef Abukamail
 */




#ifdef GROK_SNOOP

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* information necessary to understand Solaris Snoop output */
struct snoop_file_header {
    char		format_name[8];	/* should be "snoop\0\0\0" */
    tt_uint32		snoop_version;	/* current version is "2" */
    tt_uint32		mac_type;	/* hardware type */
};
/* snoop hardware types that we understand */
/* from sys/dlpi.h */
/*  -- added prefix SNOOP_ to avoid name clash */
#define	SNOOP_DL_ETHER	0x4	/* Ethernet Bus */
#define	SNOOP_DL_FDDI	0x08	/* Fiber Distributed data interface */
#define	SNOOP_DL_ATM	0x12	/* from Sun's "atmsnoop" */

struct snoop_packet_header {
    tt_uint32	len;
    tt_uint32	tlen;
    tt_uint32	blen;
    tt_uint32	unused3;
    tt_uint32	secs;
    tt_uint32	usecs;
};



/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;
static int snoop_mac_type;

/* (Courtesy Jeffrey Semke, Pittsburgh Supercomputing Center) */
/* locate ip within FDDI according to RFC 1188 */
static int find_ip_fddi(char* buf, int iplen) {
      char* ptr, *ptr2;
      int i;
      u_char pattern[] = {0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
#define FDDIPATTERNLEN 7

      ptr = ptr2 = buf;

      for (i=0; i < FDDIPATTERNLEN; i++) {
	    ptr2 = memchr(ptr,pattern[i],(iplen - (int)(ptr - buf)));
	    if (!ptr2) 
		  return (-1);
	    if (i && (ptr2 != ptr)) {
		  ptr2 = ptr2 - i - 1;
		  i = -1;
	    }
	    ptr = ptr2 + 1;
      }
      return (ptr2 - buf + 1);
      
}


/* return the next packet header */
/* currently only works for ETHERNET and FDDI */
static int
pread_snoop(
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
    struct snoop_packet_header hdr;
    int hlen;

    while (1) {
	hlen = sizeof(struct snoop_packet_header);

	/* read the packet header */
	if ((rlen=fread(&hdr,1,hlen,SYS_STDIN)) != hlen) {
	    if (rlen != 0)
		fprintf(stderr,"Bad snoop packet header\n");
	    return(0);
	}

	/* convert some stuff to host byte order */
	hdr.tlen = ntohl(hdr.tlen);
	hdr.len = ntohl(hdr.len);
	hdr.blen = ntohl(hdr.blen);
	hdr.secs = ntohl(hdr.secs);
	hdr.usecs = ntohl(hdr.usecs);

	/* truncated packet length */
	packlen = hdr.tlen;

	/* bug fix from Brian Utterback */
	/* "blen" is the "total length of the packet", header+data+padding */
	len = hdr.blen - hlen;

	if (snoop_mac_type == SNOOP_DL_ETHER) {
	    /* read the ethernet header */
	    rlen=fread(pep,1,sizeof(struct ether_header),SYS_STDIN);
	    if (rlen != sizeof(struct ether_header)) {
		fprintf(stderr,"Couldn't read ether header\n");
		return(0);
	    }

	    /* read the rest of the packet */
	    len -= sizeof(struct ether_header);
	    if (len >= IP_MAXPACKET) {
		/* sanity check */
		fprintf(stderr,
			"pread_snoop: invalid next packet, IP len is %d, return EOF\n", len);

		return(0);
	    }

	    /* add VLAN support for John Tysko */
	    if ((ntohs(pep->ether_type) == ETHERTYPE_VLAN) && (len >= 4)){
		struct {
		    tt_uint16 vlan_num;
		    tt_uint16 vlan_proto;
		} vlanh;

		/* adjust packet length */
		len -= 4;

		/* read the vlan header */
		if ((rlen=fread(&vlanh,1,sizeof(vlanh),SYS_STDIN)) != sizeof(vlanh)) {
		    perror("pread_snoop: seek past vlan header");
		}

		if ((ntohs(vlanh.vlan_proto) == ETHERTYPE_IP) ||
		    (ntohs(vlanh.vlan_proto) == ETHERTYPE_IPV6)) {
		    /* make it appear to have been IP all along */
		    /* (note that both fields are still in N.B.O. */
		    pep->ether_type = vlanh.vlan_proto;
		    if (debug > 2)
			printf("Removing VLAN header (vlan:%x)\n",
			       vlanh.vlan_num);
		} else {
		    if (debug > 2)
			printf("Skipping a VLAN packet (num:%x proto:%x)\n",
			       vlanh.vlan_num, vlanh.vlan_proto);
		}

	    } 


	    /* if it's not IP, then skip it */
	    if ((ntohs(pep->ether_type) != ETHERTYPE_IP) &&
		(ntohs(pep->ether_type) != ETHERTYPE_IPV6)) {


		if (debug > 2)
		    fprintf(stderr,
			    "pread_snoop: not an IP packet (ethertype 0x%x)\n",
			    ntohs(pep->ether_type));
		/* discard the remainder */
		/* N.B. fseek won't work - it could be a pipe! */
		if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
		    perror("pread_snoop: seek past non-IP");
		}

		continue;
	    }

	    if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
		if (rlen != 0 && debug)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
		return(0);
	    }

	    *ppip  = (struct ip *) pip_buf;
	    /* last byte in the IP packet */
	    *pplast = (char *)pip_buf+packlen-sizeof(struct ether_header)-1;

	} else if (snoop_mac_type == SNOOP_DL_FDDI) {
	    /* FDDI is different */
	    int offset;

	    /* read in the whole frame and search for IP header */
	    /* (assumes sizeof(fddi frame) < IP_MAXPACKET, should be true) */
	    if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
		if (debug && rlen != 0)
		    fprintf(stderr,
			    "Couldn't read %d more bytes, skipping last packet\n",
			    len);
		return(0);
	    }

	    /* find the offset of the IP header inside the FDDI frame */
	    if ((offset = find_ip_fddi((void *)pip_buf,len)) == -1) {
		/* not found */
		if (debug)
		    printf("snoop.c: couldn't find next IP within FDDI\n");
		return(-1);
	    }

	    /* copy to avoid alignment problems later (yucc) */
	    /* (we use memmove to make overlaps work) */
	    memmove(pip_buf,(char *)pip_buf+offset,len-offset);

	    /* point to first and last char in IP packet */
	    *ppip  = (struct ip *) ((void *)pip_buf);
	    *pplast = (char *)pip_buf+len-offset-1;

	    /* assume it's IP (else find_ip_fddi would have failed) */
	    pep->ether_type = htons(ETHERTYPE_IP);
	} else if (snoop_mac_type == SNOOP_DL_ATM) {
		/* there's a 12 byte header that we don't care about */
		/* the last 2 of those 12 bytes are the packet type */
		/* we don't care about hardware header, so we just discard */
		struct atm_header {
			u_char junk[10];
			u_short type;
		} atm_header;

		/* grab the 12-byte header */
		rlen=fread(&atm_header,1,sizeof(struct atm_header),SYS_STDIN);
		if (rlen != sizeof(struct atm_header)) {
			fprintf(stderr,"Couldn't read ATM header\n");
			return(0);
		}

		/* fill in the ethernet type */
		/* we'll just assume that they're both in the same network
		   byte order */
		pep->ether_type = atm_header.type;

		/* read the rest of the packet */
		len -= sizeof(struct atm_header);
		if (len >= IP_MAXPACKET) {
			/* sanity check */
			fprintf(stderr,
				"pread_snoop: invalid next packet, IP len is %d, return EOF\n", len);

			return(0);
		}

		/* if it's not IP, then skip it */
		if ((ntohs(pep->ether_type) != ETHERTYPE_IP) &&
		    (ntohs(pep->ether_type) != ETHERTYPE_IPV6)) {
			if (debug > 2)
				fprintf(stderr,
					"pread_snoop: not an IP packet (ethertype 0x%x)\n",
					ntohs(pep->ether_type));
			/* discard the remainder */
			/* N.B. fseek won't work - it could be a pipe! */
			if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
				perror("pread_snoop: seek past non-IP");
			}

			continue;
		}

		if ((rlen=fread(pip_buf,1,len,SYS_STDIN)) != len) {
			if (rlen != 0 && debug)
				fprintf(stderr,
					"Couldn't read %d more bytes, skipping last packet\n",
					len);
			return(0);
		}

		*ppip  = (struct ip *) pip_buf;
		/* last byte in the IP packet */
		*pplast = (char *)pip_buf+packlen-sizeof(struct ether_header)-1;
	} else {
	    printf("snoop hardware type %d not understood\n",
		   snoop_mac_type);
	   
	    exit(-1);
	}


	/* save pointer to physical header (always ethernet) */
	*pphys  = pep;
	*pphystype = PHYS_ETHER;


	ptime->tv_sec  = hdr.secs;
	ptime->tv_usec = hdr.usecs;
	*plen          = hdr.len;
	*ptlen         = hdr.tlen;


	return(1);
    }
}



/*
 * is_snoop()   is the input file in snoop format??
 */
pread_f *is_snoop(char *filename)
{
    struct snoop_file_header buf;
    int rlen;

#ifdef __WIN32
    if((fp = fopen(filename, "r")) == NULL) {
       perror(filename);
       exit(-1);
    }
#endif /* __WIN32 */   
   
    /* read the snoop file header */
    if ((rlen=fread(&buf,1,sizeof(buf),SYS_STDIN)) != sizeof(buf)) {
	rewind(SYS_STDIN);
	return(NULL);
    }

    /* first 8 characters should be "snoop\0\0\0" */
    if (strcmp(buf.format_name,"snoop") != 0)
	return(NULL);

    /* OK, it's a snoop file */


    /* convert some stuff to host byte order */
    buf.snoop_version = ntohl(buf.snoop_version);
    buf.mac_type = ntohl(buf.mac_type);
    
    /* sanity check on snoop version */
    if (debug) {
	printf("Snoop version: %ld\n", buf.snoop_version);
    }
    if (buf.snoop_version != 2) {
	printf("\
Warning! snoop file is version %ld.\n\
Tcptrace is only known to work with version 2\n",
	       buf.snoop_version);
    }

    /* sanity check on hardware type */
    snoop_mac_type = buf.mac_type;
    switch (buf.mac_type) {
      case SNOOP_DL_ETHER:
	if (debug)
	    printf("Snoop hw type: %ld (Ethernet)\n", buf.mac_type);
	break;
      case SNOOP_DL_FDDI:
	if (debug)
	    printf("Snoop hw type: %ld (FDDI)\n", buf.mac_type);
	break;
      case SNOOP_DL_ATM:
	if (debug)
	    printf("Snoop hw type: %ld (ATM)\n", buf.mac_type);
	break;
      default:
	if (debug)
	    printf("Snoop hw type: %ld (unknown)\n", buf.mac_type);
	printf("snoop hardware type %ld not understood\n", buf.mac_type);
       
	exit(-1);
    }


    /* OK, it's mine.  Init some stuff */
    pep = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    

    return(pread_snoop);
}
#endif /* GROK_SNOOP */
