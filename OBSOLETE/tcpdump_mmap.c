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
#include <sys/stat.h>
#include <sys/mman.h>


static struct ether_header *pep_buf;
static struct ip *pip_buf;

/* the memory mapped dump file */
char *pdumpfile;
char *pdumpfile_ptr;
char *pdumpfile_end;
int dumpfilesize;


/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_tcpdump(
    struct timeval	*ptime,
    int		 	*plen,
    int		 	*ptlen,
    void		**pphys,
    int			*pphystype,
    struct ip		**ppip)
{
    int len;
    struct packet_header hdr;
    struct packet_header *phdr;
    struct ip *pip;
    struct ether_header *pep;

    while (1) {  /* loop until we find an IP packet */
	/* check for "EOF" */
	if ((unsigned)pdumpfile_ptr > (unsigned)pdumpfile_end)
	    return(0);  /* EOF */

	/* grab the packet header */
	phdr = (struct packet_header *) pdumpfile_ptr;
	pdumpfile_ptr += sizeof(struct packet_header);

	/* check alignment */
	if (((unsigned)phdr & 3) != 0) {   /* need 4 byte aligned */
	    if (debug) printf("tcpdump_read: copying packet header\n");
	    memcpy(&hdr,phdr,sizeof(hdr));
	    phdr = &hdr;
	}

	/* convert the packet header to local byte order */
	if (tcpdump_doswap)
	    swap_phdr(phdr);
	len = phdr->caplen;

	/* check again for "EOF" */
	if ((unsigned)pdumpfile_ptr+len > (unsigned)pdumpfile_end)
	    return(0);  /* EOF */

	/* grab the ethernet header */
	pep = (struct ether_header *) pdumpfile_ptr;

	/* grab the IP header */
	pip = (struct ip *) (pdumpfile_ptr+sizeof(struct ether_header));

	/* the whole point of memory mapping is to avoid copies, but */
	/* because all "real machines" (TM) these days run RISC */
	/* processors and RISC machines are picky about alignment */
	/* we'll do copying if the alignment is off */
	/* check again for "EOF" */
	if (((unsigned)pep & 1) != 0) {  /* need 2 byte aligned */
	    if (debug>2)
		printf("tcpdump_read: copying ethernet header from 0x%08x\n",
		       (unsigned) pep);
	    memcpy(pep_buf,pep,sizeof(struct ether_header));
	    pep = pep_buf;
	} else if (debug>2) {
	    printf("tcpdump_read: SKIPPING copying ethernet header\n");
	}
	if (((unsigned)pip & 3) != 0) {   /* need 4 byte aligned */
	    if (debug>2)
		printf("tcpdump_read: copying IP header from 0x%08x\n",
		       (unsigned) pip);
	    memcpy(pip_buf,pip,len-sizeof(struct ether_header));
	    pip = pip_buf;
	} else if (debug>2) {
	    printf("tcpdump_read: SKIPPING copying IP header\n");
	}


	/* save the answers */
	ptime->tv_sec  = phdr->ts_secs;
	ptime->tv_usec = phdr->ts_usecs;
	*plen          = phdr->caplen;
	*ptlen         = phdr->len;


	*ppip  = (struct ip *) pip;
	*pphys  = pep;
	*pphystype = PHYS_ETHER;

	/* if it's not TCP/IP, then skip it */
	if ((ntohs(pep->ether_type) != ETHERTYPE_IP) ||
	    ((*ppip)->ip_p != IPPROTO_TCP))
	    continue;

	/* update the stdin pointer in case the user is watching progress */
	if (FALSE && printticks)
	    (void) fseek(stdin,
			 (unsigned)pdumpfile_ptr - (unsigned)pdumpfile,
			 SEEK_SET);

	if (debug>2)
	    printf("tcpdump_read: returning packet\n");

	pdumpfile_ptr += len;

	return(1);
    }
}



int (*is_tcpdump(void))()
{
    struct dump_file_header dfh;
    struct stat stat;
    int rlen;

    if (debug)
	printf("Using 'mmap' version of tcpdump\n");

    /* read the file header */
    if ((rlen=fread(&dfh,1,sizeof(dfh),stdin)) != sizeof(dfh)) {
	rewind(stdin);
	return(NULL);
    }

    if (dfh.magic == TCPDUMP_MAGIC) {
	if (debug)
	    printf("tcpdump_mmap: saw magic number (native byte order)\n");
	tcpdump_doswap = FALSE;
    } else if (SWAPLONG(dfh.magic) == TCPDUMP_MAGIC) {
	if (debug)
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

    /* check the dump file length */
    if (fstat(0,&stat) == -1) {
	perror("stdin");
	exit(1);
    }

    dumpfilesize = (int)stat.st_size;

    if (debug)
	printf("Dump file is %d bytes long\n", dumpfilesize);

    /* memory map the input file */
    pdumpfile = mmap((caddr_t) 0,	/* put it anywhere	*/
		     stat.st_size,	/* fixed size		*/
		     PROT_READ,		/* rdonly or r/w	*/
		     MAP_PRIVATE|MAP_NORESERVE,
		     			/* sharing		*/
		     0,			/* attach to 'fd'	*/
		     (off_t) 0);	/* ... offset 0 in 'fd'	*/
    if ((int)pdumpfile == -1) {
	perror("mmap");
	exit(-1);
    }
    pdumpfile_end = pdumpfile+stat.st_size;
    pdumpfile_ptr = pdumpfile + sizeof(dfh);
    if (debug)
	printf("packet file mmap()ed from 0x%08lx to 0x%08lx\n",
	       (u_long) pdumpfile, (u_long) pdumpfile_end);
    
    

    /* OK, it's mine.  Init some stuff */
    pep_buf = MallocZ(sizeof(struct ether_header));
    pip_buf = MallocZ(IP_MAXPACKET);
    
    return(pread_tcpdump);
}


#endif /* GROK_TCPDUMP */
