/*
 *
 * Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
 *                    All rights reserved.
 *
 * This software and documentation has been developed by Endace Technology Ltd.
 * along with the DAG PCI network capture cards. For further information please
 * visit http://www.endace.com/.
 *
 * Redistribution and use of software in source and binary forms and
 * documentation, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * 1. Redistributions of source code and documentation must retain the above
 *    copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Endace Technology Ltd.,
 *      Hamilton, New Zealand, and its contributors.
 * 4. Neither the name of Endace Technology nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE AND DOCUMENTATION IS PROVIDED BY ENDACE TECHNOLOGY AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ENDACE TECHNOLOGY
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2003 -- Endace Technology Ltd, Hamilton, New Zealand\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";

/* 
 * erf - Endace ERF (Extensible Record Format) specific file reading stuff
 */


#ifdef GROK_ERF

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* Record type defines */
#define TYPE_LEGACY       0
#define TYPE_HDLC_POS     1
#define TYPE_ETH          2
#define TYPE_ATM          3
#define TYPE_AAL5         4

typedef struct pos_rec {
    unsigned int	hdlc;
    unsigned char	pload[1];
} pos_rec_t;

typedef struct eth_rec {
    unsigned char	offset;
    unsigned char	pad;
    unsigned char	dst[6];
    unsigned char	src[6];
    unsigned short	etype;
    unsigned char	pload[1];
} eth_rec_t;

typedef struct atm_rec {
    unsigned int	header; 
    unsigned char	pload[1];
} atm_rec_t;

#ifdef HAVE_LONG_LONG
typedef unsigned long long erf_timestamp_t;
#else
typedef unsigned long erf_timestamp_t[2];
#endif

typedef struct erf_record {
    erf_timestamp_t	ts;
    unsigned char	type;
    unsigned char	flags;
    unsigned short	rlen;
    unsigned short	lctr;
    unsigned short	wlen;
    union {
        pos_rec_t	pos;
        eth_rec_t	eth;
        atm_rec_t	atm;
    } rec;
} erf_record_t;

#define ERF_HEADER_LEN		16
#define MAX_RECORD_LEN		0x10000 /* 64k */
#define RECORDS_FOR_ERF_CHECK	3
#define FCS_BITS		32

#ifndef min
#define min(a, b) ((a) > (b) ? (b) : (a))
#endif

/*
 * ATM snaplength
 */
#define ATM_SNAPLEN		48

/*
 * Size of ATM payload 
 */
#define ATM_SLEN(h)		ATM_SNAPLEN
#define ATM_WLEN(h)		ATM_SNAPLEN

/*
 * Size of Ethernet payload
 */
#define ETHERNET_WLEN(h)	(ntohs((h)->wlen) - (fcs_bits >> 3))
#define ETHERNET_SLEN(h) 	min(ETHERNET_WLEN(h), ntohs((h)->rlen) - ERF_HEADER_LEN - 2)

/*
 * Size of HDLC payload
 */
#define HDLC_WLEN(h)		(ntohs((h)->wlen) - (fcs_bits >> 3))
#define HDLC_SLEN(h)		min(HDLC_WLEN(h), ntohs((h)->rlen) - ERF_HEADER_LEN)

static struct ether_header eth_header;
static erf_record_t *record;
static int records_for_erf_check = RECORDS_FOR_ERF_CHECK;
static int fcs_bits = FCS_BITS;

/*
 * Convert little-endian to host order.
 */
#ifdef HAVE_LONG_LONG
#define pletohll(p) ((unsigned long long)*((const unsigned char *)(p)+7)<<56|  \
                     (unsigned long long)*((const unsigned char *)(p)+6)<<48|  \
                     (unsigned long long)*((const unsigned char *)(p)+5)<<40|  \
                     (unsigned long long)*((const unsigned char *)(p)+4)<<32|  \
                     (unsigned long long)*((const unsigned char *)(p)+3)<<24|  \
                     (unsigned long long)*((const unsigned char *)(p)+2)<<16|  \
                     (unsigned long long)*((const unsigned char *)(p)+1)<<8|   \
                     (unsigned long long)*((const unsigned char *)(p)+0)<<0)
#else
#define pletohl(p)  ((unsigned long)*((const unsigned char *)(p)+3)<<24|  \
                     (unsigned long)*((const unsigned char *)(p)+2)<<16|  \
                     (unsigned long)*((const unsigned char *)(p)+1)<<8|   \
                     (unsigned long)*((const unsigned char *)(p)+0)<<0)
#endif

/* return the next packet header */
static int
pread_erf(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip,
    void		**pplast)
{
    int rlen, psize;
    unsigned short ether_type = 0;

    /* read the next frames */
    while (1) {
        if ((rlen=fread(record,1,ERF_HEADER_LEN,SYS_STDIN)) != ERF_HEADER_LEN) {
            if (debug && (rlen != 0))
                fprintf(stderr,"Bad ERF packet header (len:%d)\n", rlen);
            return(0);
        }
        psize = ntohs(record->rlen) - ERF_HEADER_LEN;
        if ((rlen=fread((char *)record+ERF_HEADER_LEN,1,psize,SYS_STDIN)) != psize) {
            if (debug && (rlen != 0))
                fprintf(stderr,"Bad ERF packet payload (len:%d)\n", rlen);
            return(0);
        }

#ifdef HAVE_LONG_LONG
        {
            unsigned long long ts = pletohll(&record->ts);

            ptime->tv_sec = ts >> 32;
            ts = ((ts &  0xffffffffULL) * 1000 * 1000);
            ts += (ts & 0x80000000ULL) << 1; /* rounding */
            ptime->tv_usec = ts >> 32;		
            if (ptime->tv_usec >= 1000000) {
                ptime->tv_usec -= 1000000;
                ptime->tv_sec += 1;
            }
        }
#else
        ptime->tv_sec = pletohl(&record->ts[1]);
        ptime->tv_usec =
            (unsigned long)((pletohl(&record->ts[0])*1000000.0)/0xffffffffUL);
#endif

        switch (record->type) {
          case TYPE_ATM:
            *ptlen = ATM_SLEN(record);
            *plen = ATM_WLEN(record);
            *pphys = &eth_header;
            ether_type = ntohs(((unsigned short *)&record->rec.atm.pload)[3]);
            *ppip = (struct ip *)&record->rec.atm.pload[8]; /* skip snap/llc */
            *pplast = ((char *)*ppip)+*ptlen-8-1;
            break;
          case TYPE_ETH:
            *ptlen = ETHERNET_SLEN(record);
            *plen = ETHERNET_WLEN(record);
            *pphys  = &record->rec.eth.dst;
            ether_type = ntohs(record->rec.eth.etype);
            *ppip = (struct ip *)&record->rec.eth.pload[0];
            *pplast = ((char *)*ppip)+*ptlen-sizeof(struct ether_header)-1;
            break;
          case TYPE_HDLC_POS:
            *ptlen = HDLC_SLEN(record);
            *plen = HDLC_WLEN(record);
            *pphys = &eth_header;
            /* Detect PPP and convert the Ethertype value */
            if (ntohs(((unsigned short *)&record->rec.pos.hdlc)[0]) == 0xff03) {
              if (ntohs(((unsigned short *)&record->rec.pos.hdlc)[1]) == 0x0021) {
                ether_type = ETHERTYPE_IP;
              }
            } else {
              ether_type = ntohs(((unsigned short *)&record->rec.pos.hdlc)[1]);
            }
            *ppip = (struct ip *)&record->rec.pos.pload[0];
            *pplast = ((char *)*ppip)+*ptlen-4-1;
            break;
          default:
            fprintf(stderr,"Unsupported ERF record type %d\n", record->type);
            exit(1);
        }

        *pphystype = PHYS_ETHER;

        /* if it's not IP, then skip it */
        if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
            if (debug > 2)
                fprintf(stderr,"pread_erf: not an IP packet\n");
            continue;
        }

        return(1);
    }
}

/*
 * is_erf()   is the input file in ERF format?
 */
pread_f *
is_erf(
    char	*filename)
{
    int i, rlen;
    int psize, n;
    char *s;
    erf_timestamp_t prevts;

    memset(&prevts, 0, sizeof(prevts));

#ifdef __WIN32
    if((fp = fopen(filename, "r")) == NULL) {
       perror(filename);
       exit(-1);
    }
#endif /* __WIN32 */   

    /*
     * The wirelength value in the ERF file is needed to calculate the
     * original payload length. Unfortunately the value includes a
     * 0, 2 or 4 byte checksum for Ethernet and PoS, and there is no
     * way of telling which it is. So assume 4 bytes checksum unless
     * told differently through the environment.
     */
    if ((s = getenv("ERF_FCS_BITS")) != NULL) {
        if ((n = atoi(s)) == 0 || n == 16|| n == 32) {
            fcs_bits = n;
        }
    }

    /* number of records to scan before deciding if this really is ERF (dflt=3) */
    if ((s = getenv("ERF_RECORDS_TO_CHECK")) != NULL) {
        if ((n = atoi(s)) > 0 && n < 101) {
            records_for_erf_check = n;
        }
    }

    if (record == NULL && (record = malloc(MAX_RECORD_LEN)) == NULL) {
        fprintf(stderr,"No memory for ERF record buffer\n");
        exit(1);
    }

    /* ERF is a little hard because there's no magic number */

    for (i = 0; i < records_for_erf_check; i++) {
        erf_timestamp_t ts;

        if ((rlen=fread(record,1,ERF_HEADER_LEN,SYS_STDIN)) != ERF_HEADER_LEN) {
            if (rlen == 0) {
                break; /* eof */
            } else {
                rewind(SYS_STDIN);
                return(NULL);
            }
        }

        /* fail on invalid record type, decreasing timestamps or non-zero pad-bits */
        if (record->type == 0 || record->type > TYPE_AAL5 || (record->flags & 0xc0) != 0) {
            rewind(SYS_STDIN);
            return(NULL);
        }

#ifdef HAVE_LONG_LONG
        if ((ts = pletohll(&record->ts)) < prevts) {
            rewind(SYS_STDIN);
            return(NULL);
        }
#else
        ts[0] = pletohl(&record->ts[0]); /* frac */
        ts[1] = pletohl(&record->ts[1]); /* sec */

        if ((ts[1] < prevts[1]) || (ts[1] == prevts[1] && ts[0] < prevts[0])) {
            rewind(SYS_STDIN);
            return(NULL);
        }
#endif
        memcpy(&prevts, &ts, sizeof(prevts));

        psize = ntohs(record->rlen) - ERF_HEADER_LEN;
        if ((rlen=fread((char *)record+ERF_HEADER_LEN,1,psize,SYS_STDIN)) != psize) {
            rewind(SYS_STDIN);
            return(NULL);
        }
    }
    rewind(SYS_STDIN);

    /* There may be no physical header present, so make up one */
    memset(&eth_header, 0, sizeof(eth_header));
    eth_header.ether_type = htons(ETHERTYPE_IP);

    if (debug)
        fprintf(stderr,"ERF format\n");

    return(pread_erf);
}

#endif /* GROK_ERF */
