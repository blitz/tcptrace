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
 * nlanr - TSH specific file reading stuff
 */

/* TSH header format:
 *        0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 0  |                    timestamp (seconds)                        | Time
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 1  |  interface #  |          timestamp (microseconds)             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 2  |Version|  IHL  |Type of Service|          Total Length         | IP
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 3  |         Identification        |Flags|      Fragment Offset    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 4  |  Time to Live |    Protocol   |         Header Checksum       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 5  |                       Source Address                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 6  |                    Destination Address                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 7  |          Source Port          |       Destination Port        | TCP
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 8  |                        Sequence Number                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 9  |                    Acknowledgment Number                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  Data |           |U|A|P|R|S|F|                               |
 * 10 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *    |       |           |G|K|H|T|N|N|                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */





#ifdef GROK_NLANR

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* information necessary to understand NLANL Tsh output */
#define TSH_DUMP_OFFSET 16
struct tsh_packet_header {
    unsigned int	ts_secs;
#ifdef _BIT_FIELDS_LTOH
    unsigned int	interface_id:8;
    unsigned int	ts_usecs:24;
#else
    unsigned int	ts_usecs:24;
    unsigned int	interface_id:8;
#endif
};

struct tsh_frame {
    struct tsh_packet_header tph;
    struct ip ip_header;
    struct tcphdr tcp_header;  /* just the first 16 bytes present */
};


/* static buffers for reading */
static struct ether_header *pep;

/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_nlanr(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int rlen;
    static struct tsh_frame hdr;
    int packlen = sizeof(struct ip) + sizeof(struct tcphdr);
    int hlen = 44;

    /* read the next frames */
    if ((rlen=fread(&hdr,1,hlen,SYS_STDIN)) != hlen) {
	if (debug && (rlen != 0))
	    fprintf(stderr,"Bad tsh packet header (len:%d)\n", rlen);
	return(0);
    }

    /* grab the time */
    ptime->tv_sec  = hdr.tph.ts_secs;
    ptime->tv_usec = hdr.tph.ts_usecs;

    /* truncated length is just an IP header and a TCP header */
    *ptlen         = packlen;

    /* original length is from the IP header */
    *plen          = hdr.ip_header.ip_len;


    /* Here's the IP/TCP stuff */
    *ppip  = &hdr.ip_header;

    /* Here's the last byte of the packet */
    *pplast = (char *)(*ppip)+packlen-1;

    /* here's the (pseudo) ethernet header */
    *pphys  = pep;
    *pphystype = PHYS_ETHER;

    return(1);
}



/*
 * is_nlanr()   is the input file in tsh format??
 */
pread_f *is_nlanr(char *filename)
{
    struct tsh_frame tf;
    int rlen;
   
#ifdef __WIN32
    if((fp = fopen(filename, "r")) == NULL) {
       perror(filename);
       exit(-1);
    }
#endif /* __WIN32 */   

    /* tsh is a little hard because there's no magic number */
    

    /* read the tsh file header */
    if ((rlen=fread(&tf,1,sizeof(tf),SYS_STDIN)) != sizeof(tf)) {
	/* not even a full frame */
	rewind(SYS_STDIN);
	return(NULL);
    }
    rewind(SYS_STDIN);

    if (debug) {
	printf("nlanr tsh ts_secs:   %d\n", tf.tph.ts_secs);
	printf("nlanr tsh ts_usecs:  %d\n", tf.tph.ts_usecs);
	printf("nlanr tsh interface: %d\n", tf.tph.interface_id);
	printf("nlanr sizeof(tf):    %d\n", sizeof(tf));
	printf("nlanr sizeof(tph):   %d\n", sizeof(tf.tph));
	if (debug > 1)
	    PrintRawDataHex("NLANR TSH header",&tf,(char *)&tf+39);
    }

    /* quick heuristics */
    if (((tf.ip_header.ip_v != 4) && (tf.ip_header.ip_v != 6))
	) {
	return(NULL);
    }


    /* OK, let's hope it's a tsh file */


    /* there's no physical header present, so make up one */
    pep = MallocZ(sizeof(struct ether_header));
    pep->ether_type = htons(ETHERTYPE_IP);

    if (debug)
	fprintf(stderr,"TSH format, interface ID %d\n", tf.tph.interface_id);


    return(pread_nlanr);
}
#endif /* GROK_NLANR */
