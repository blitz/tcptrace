/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998
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


/* routines that were missing somewhere.  Not really part of the
   distribution, but an attempt to help out people that want to port
   this thing  */

#include "tcptrace.h"

/*
 * According to Rich Jones at HP, there is no ether_ntoa under HPUX.
 */
#ifdef __hpux
#undef HAVE_ETHER_NTOA
#endif /* __hpux */



#ifndef HAVE_ETHER_NTOA
/* ether_ntoa doesn't exist on at least some HP machines. */
/* how about: */

char *
ether_ntoa (struct ether_addr *e)
{
    unsigned char *pe;
    static char buf[30];

    pe = (unsigned char *) e;
    sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",
	    pe[0], pe[1], pe[2], pe[3], pe[4], pe[5]);
    return(buf);
}
#endif /* !HAVE_ETHER_NTOA */
