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
