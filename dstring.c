/* simple, dynamic string support for C */
/* wow, never thought that I'd long for C++ when working on tcptrace :-) */
#include "tcptrace.h"


/* our dynamic string structure */
struct dstring {
    char *buf;
    int ix_nextch;
    int buflen;
};


/* local routines */
static void DSExpand(struct dstring *pds);

/* make the total string size longer */
static void
DSExpand(struct dstring *pds)
{
    unsigned newsize;
    char *newbuf;
    
    /* choose a new size */
    if (pds->buflen == 0)
	newsize = 64;
    else if (pds->buflen < (16*1024))
	newsize = pds->buflen * 2;
    else
	newsize = pds->buflen +(4*1024);

    /* make the new buffer (using the old one if possible) */
    newbuf = ReallocZ(pds->buf,pds->buflen,newsize);

    pds->buflen = newsize;
    pds->buf = newbuf;
}






/* Make a new dstring */
struct dstring *
DSNew(void)
{
    struct dstring *pret;

    /* malloc and zero out */
    pret = MallocZ(sizeof(struct dstring));

    return(pret);
}



/* Destroy a dstring */
void
DSDestroy(struct dstring **ppds)
{
    free((*ppds)->buf);
    free((*ppds));
    *ppds = NULL;
}




/* erase the string, but leave the structure otherwise intact */
void
DSErase(
    struct dstring *pds)
{
    pds->ix_nextch = 0;
}



/* append a character to a dstring */
void
DSAppendChar(
    struct dstring *pds,
    char ch)
{
    /* status:
       buf[0,1,2,...(buflen-1)] are valid
       buf[ix_nextch] is where the next character should go
       if (ix_nextch > (buflen-1)), then it's full
       same as (ix_nextch+1 > (buflen))
    */
    if (1 /* for the null */ + pds->ix_nextch+1 > pds->buflen) {
	DSExpand(pds);
    }

    pds->buf[pds->ix_nextch++] = ch;
    pds->buf[pds->ix_nextch] = '\00'; /* keep it NULL terminated */
}



/* append a normal string to the end of a dstring */
void
DSAppendString(
    struct dstring *pds,
    char *str)
{
    while (*str) {
	DSAppendChar(pds,*str);
	++str;
    }
}


/* append at most 'len' characters from a normal string to a dstring */
void
DSAppendStringN(
    struct dstring *pds,
    char *str,
    int len)
{
    while (*str) {
	if (len-- <= 0)
	    break;
	DSAppendChar(pds,*str);
	++str;
    }
}


/* return the value of the string */
char *
DSVal(
    struct dstring *pds)
{
    if (pds->buflen)
	return(pds->buf);
    else
	return("");		/* not used yet, treat as null */
}
