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

/* dynamic counters/arrays */
/* uses a 10-ary tree to manage a sparse counter space */
#include "dyncounter.h"


static int ldebug = 0;

/* external routines */
void *MallocZ(int nbytes);


/* WIDTH of the nodes (designed for 10, caveat emptor!) */
/* (sdo: tested at 2, 5, 10, 100) */
#define CARDINALITY 10


/* 10-ary tree node */
struct node {
    u_long depth;		/* 1, 10, 100, 1000 ... 10,000,000 */
    union {
	struct node *down[CARDINALITY];	/* if depth != 1 */
	u_long value[CARDINALITY];	/* if depth == 1 */
    } un;

    struct node *nextleaf;	/* linked list of leaves, for NextCounter() */
    u_long prefix;		/* from trees above */
};


/* dynamically-sized counter structure */
struct dyn_counter {
    u_long gran;		/* granularity of the IX */
    u_long maxix;		/* NOT scaled */
    u_long minix;		/* NOT scaled */
    u_long maxcount;
    u_long total_count;		/* sum of the "AddToCounters" call values */
    struct node *tree;

    /* linked list of leaves */
    struct node *firstleaf;
    struct node *lastleaf;
};


/* local routines */
static struct dyn_counter *MakeCounterStruct(void);
static struct node *NewNode(u_long depth);
static u_long *FindTwig(struct node *lastnode, u_long ix);
static struct node *FindLeaf( struct dyn_counter *pdc, struct node **ptree,
			      u_long depth, u_long value, int fcreate);
static u_long *FindCounter(struct dyn_counter **ppdc, u_long ix, int fcreate);
static void PrintTree(struct node *tree);
static void PrintTreeRecurse(struct node *tree, u_long depth);
static void FinishTree(struct dyn_counter *pdc);
static void FinishTreeRecurse(struct dyn_counter *pdc, struct node *pnode,
			      u_long prefix, u_long depth);
static void PrintLeafList(struct dyn_counter *pdc);
static struct node *NextCounterRecurse(struct node *node, u_long nextix,
				       u_long *pix, u_long *pcount);
static struct node *MakeDepth(struct node *node, u_long depth);
static void DestroyTree(struct node *pnode);
static void MakeCounter(struct dyn_counter **ppdc, u_long ix,
			u_long val, u_long granularity, char set);






/* add a value to a counter */
void
AddToCounter(
    struct dyn_counter **ppdc,
    u_long ix,
    u_long val,
    u_long granularity)
{
    if (ldebug)
	fprintf(stderr,"AddToCounter(%p, %lu, %lu) called\n", *ppdc, ix, val);

    MakeCounter(ppdc,ix,val,granularity,0);
}



/* set a value in a counter */
void
SetCounter(
    struct dyn_counter **ppdc,
    u_long ix,
    u_long val,
    u_long granularity)
{
    if (ldebug)
	fprintf(stderr,"SetCounter(%p, %lu, %lu) called\n", *ppdc, ix, val);

    MakeCounter(ppdc,ix,val,granularity,1);
}



/* read only, doesn't MAKE anything */
u_long
LookupCounter(
    struct dyn_counter *pdc,
    u_long ix)
{
    u_long *pdigit;

    if (ldebug)
	fprintf(stderr,"LookupCounter(p,%lu) called\n", ix);

    /* try to find the counter */
    pdigit = FindCounter(&pdc,
			 ix,
			 0);	/* do NOT create */

    if (pdigit == NULL) {
	/* no leaf node == no such counter */
	if (ldebug)
	    fprintf(stderr,"LookupCounter(p,%lu): no such leaf\n", ix);
	return(0);
    }

    return(*pdigit);
}


int
NextCounter(
    struct dyn_counter **ppdc,
    void *pvoidcookie,
    u_long *pix,
    u_long *pcount)
{
    struct dyn_counter *pdc;
    struct node *node;
    u_long nextix;

    if (ldebug)
	fprintf(stderr,"NextCounter(p,%p,%lu,%lu) called\n",
		*((char **)pvoidcookie), *pix, *pcount);

    /* if the counter tree doesn't exist yet, create it */
    if (*ppdc == NULL) {
	*ppdc = MakeCounterStruct();
    }
    pdc = *ppdc;

    /* scale ix by granularity */
    *pix /= pdc->gran;

    /* make sure the linked list of leaves is up to date */
    if (pdc->firstleaf == NULL) {
	FinishTree(pdc);
	if (ldebug) {
	    PrintLeafList(pdc);
	    PrintTree(pdc->tree);
	}
    }

    /* if cookie is NULL, start at the head */
    if ((*((struct node **)pvoidcookie)) == NULL) {
	node = pdc->firstleaf;
	nextix = 0;
    } else {
	node = *((struct node **)pvoidcookie);
	nextix = ((*pix) % CARDINALITY) + 1;
    }


    /* sanity check on cookie */
    if (node->depth != 1) {
	fprintf(stderr,"NextCounter: invalid cookie!\n");
	exit(1);
    }

    /* recurse and solve */
    node = NextCounterRecurse(node,nextix,pix,pcount);

    if (node == NULL)
	return(0);		/* no more */

    /* scale ix by granularity */
    *pix *= pdc->gran;

    /* remember cookie for next time */
    *((struct node **)pvoidcookie) = node;

    return(1);
}


/* access routine - maximum counter value */
u_long
GetMaxCount(
    struct dyn_counter *pdc)
{
    return(pdc->maxcount);
}


/* access routine - return MAX index */
u_long
GetMaxIx(
    struct dyn_counter *pdc)
{
    return(pdc->maxix);
}


/* access routine - return MIN index */
u_long
GetMinIx(
    struct dyn_counter *pdc)
{
    return(pdc->minix);
}


/* access routine - return stored granularity */
u_long
GetGran(
    struct dyn_counter *pdc)
{
    if (pdc == NULL)
	return(1);
    return(pdc->gran);
}


/* access routine - total value added with AddToCounter() */
u_long
GetTotalCounter(
    struct dyn_counter *pdc)
{
    if (pdc == NULL)
	return(0);
    return(pdc->total_count);
}


void
DestroyCounters(
    dyn_counter *phandle)
{
    if (!*phandle)
	return;
    
    if ((*phandle)->tree)
	DestroyTree((*phandle)->tree);

    free(*phandle);
    *phandle = NULL;
}


static struct dyn_counter *
MakeCounterStruct()
{
    struct dyn_counter *pdc = MallocZ(sizeof(struct dyn_counter));

    pdc->minix = 0xffffffff;

    return(pdc);
}


static void
DestroyTree(
    struct node *pnode)
{
    int i;

    if (pnode == NULL)
	return;
    
    if (pnode->depth > 1) {
	/* recurse and delete */
	for (i=0; i < CARDINALITY; ++i) {
	    DestroyTree(pnode->un.down[i]);
	}
    }

    /* destroy ME */
    free(pnode);
    return;
}





/* the heart of the routines, a 10-ary recursize search */
static struct node *
FindLeaf(
    struct dyn_counter *pdc,
    struct node **ptree,
    u_long depth,
    u_long value,
    int fcreate)
{
    u_long hidigit;
    u_long lowdigits;
    u_long valdepth;
    u_long valunits;
    u_long temp_value;

    if (ldebug)
	fprintf(stderr,"FindLeaf(%p(depth %lu), %lu, %s) called\n",
		*ptree,
		*ptree?((*ptree)->depth):0,
		value,
		fcreate?"CREATE":"NOCREATE");


    /* if the tree is empty and we haven't asked to "create", then not found */
    if ((*ptree == NULL) && (!fcreate))
	return(NULL);

    /* determine the units of the MSDigit (the depth) */
    valdepth = 1;
    valunits = 1;
    temp_value = value;
    while (temp_value >= CARDINALITY) {
	temp_value /= CARDINALITY;
	++valdepth;
	valunits *= CARDINALITY;
    }

    if (ldebug)
	fprintf(stderr,"FindLeaf: value:%lu  depth:%lu  units:%lu\n",
		value, valdepth, valunits);


    /* is the tree deep enough? */
    if ((*ptree == NULL) || (valdepth > (*ptree)->depth)) {
	u_long correct_depth;

	/* the correct depth is the MAX of: */
	/* - the depth of the number we're looking for */
	/* - the value of "depth" passed down */
	correct_depth = depth;
	if (valdepth > correct_depth)
	    correct_depth = valdepth;

	/* if the tree isn't that deep and we haven't asked to create, then not found */
	if (!fcreate)
	    return(NULL);

	/* increase the depth of this branch */
	*ptree = MakeDepth((*ptree), correct_depth);

	/* linked list of leaves no longer valid! */
	pdc->firstleaf = NULL;

	/* adjust */
	depth = correct_depth;
    }

    /* if we're at the leaf depth, then we're done */
    if ((*ptree)->depth == 1)
	return(*ptree);

    /* if the "depth" of val is less than the depth of this node,
       recurse down the "0" branch without changing the number */
    if (valdepth < (*ptree)->depth) {
	return(FindLeaf(pdc,
			&(*ptree)->un.down[0],
			depth-1,
			value,
			fcreate));
    }

    /* (else), already the correct level */

    /* break the number into the MSDigit and LSDigits */
    hidigit = value / valunits;
    lowdigits = value % valunits;

    if (ldebug)
	fprintf(stderr,"for value %lu,  depth:%lu  units:%lu  hidigit:%lu  lowdigits:%lu\n",
		value, valdepth, valunits, hidigit, lowdigits);

    /* recurse */
    return(FindLeaf(pdc,
		    &(*ptree)->un.down[hidigit],
		    depth-1,
		    lowdigits,
		    fcreate));
}

static struct node *
MakeDepth(
    struct node *node,
    u_long depth)
{
    struct node *newroot;

    if ((node != NULL) && (node->depth >= depth))
	return(node);

    /* ELSE, insert a new level and recurse */
    newroot = NewNode(depth);
    
    /* attach the old part of the tree */
    if (depth > 1)
	newroot->un.down[0] = MakeDepth(node,depth-1);

    /* return the new root */
    return(newroot);
}
    



static struct node *
NewNode(
    u_long depth)
{
    struct node *pn;

    if (ldebug)
	fprintf(stderr,"NewNode(%lu) called\n", depth);

    pn = MallocZ(sizeof(struct node));

    pn->depth = depth;

    return(pn);
}


static u_long *
FindTwig(
    struct node *lastnode,
    u_long ix)
{
    unsigned digit;

    if (ldebug)
	fprintf(stderr,"FindTwig(%p(depth %lu), %lu) called\n",
		lastnode, lastnode->depth, ix);

    if (lastnode->depth != 1) {
	fprintf(stderr,"FindTwig: internal error, not at a leaf node\n");
	exit(2);
    }

    digit = ix % CARDINALITY;
    return(&(lastnode->un.value[digit]));
}


static u_long *
FindCounter(
    struct dyn_counter **ppdc,
    u_long ix,
    int fcreate)
{
    struct dyn_counter *pdc;
    struct node *pnode;
    u_long *pcounter;

    if (ldebug)
	fprintf(stderr,"FindCounter(p, %lu) called\n", ix);

    /* if the counter tree doesn't exist yet, create it */
    if (*ppdc == NULL) {
	*ppdc = MakeCounterStruct();
    }
    pdc = *ppdc;

    /* track MAX and MIN */
    if (ix > pdc->maxix)
	pdc->maxix = ix;
    if (ix < pdc->minix)
	pdc->minix = ix;

    if (ldebug>1)
	PrintTree(pdc->tree);

    /* scale (TRUNCATE) the index by the granularity */
    ix /= (*ppdc)->gran;

    /* find the leaf node */
    pnode = FindLeaf(pdc, &pdc->tree,
		     pdc->tree?pdc->tree->depth:1,
		     ix, fcreate);
    if (pnode == NULL)
	return(NULL);

    /* find the right counter */
    pcounter = FindTwig(pnode, ix);

    return(pcounter);
}


static void Indent(int depth)
{
    int i;

    for (i=0; i < depth; ++i)
	fputc(' ', stderr);
}


static void PrintTree(
    struct node *tree)
{
    PrintTreeRecurse(tree,0);
}


static void
PrintTreeRecurse(
    struct node *tree,
    u_long indent)
{
    int i;

    if (tree == NULL) {
	Indent(indent);
	fprintf(stderr,"NULL\n");
	return;
    }

    Indent(indent);
    fprintf(stderr,"Node %p, depth:%lu, prefix:%lu\n", tree, tree->depth, tree->prefix);

    if (tree->depth == 1) {
	for (i=0; i < CARDINALITY; ++i) {
	    Indent(indent);
	    fprintf(stderr,"Leaf[%d]: %lu (value:%lu)\n",
		    i,
		    tree->un.value[i],
		    tree->prefix*CARDINALITY+i);
	}
    } else {
	for (i=0; i < CARDINALITY; ++i) {
	    Indent(indent);
	    fprintf(stderr,"Branch %d (prefix %lu, depth %lu)\n",
		    i, tree->prefix*CARDINALITY+i, tree->depth);
	    PrintTreeRecurse(tree->un.down[i],
			     indent+3);
	}
    }
}


static void
FinishTree(
    struct dyn_counter *pdc)
{
    FinishTreeRecurse(pdc, pdc->tree, 0, pdc->tree->depth);
}


static void
FinishTreeRecurse(
    struct dyn_counter *pdc,
    struct node *pnode,
    u_long prefix,
    u_long depth)
{
    int i;

    /* special case, empty tree */
    if (pnode == NULL)
	return;

    /* sanity check, verify depth */
    if (pnode->depth != depth) {
	fprintf(stderr,"FinishTree: bad depth at node %p (%lu should be %lu)\n",
		pnode, pnode->depth, depth);
	PrintTree(pdc->tree);
	exit(-3);
    }

    /* insert prefix */
    pnode->prefix = prefix;

    /* if we're a leaf, add to end of the list */
    if (pnode->depth == 1) {
	if (pdc->firstleaf == NULL) {
	    pdc->firstleaf = pdc->lastleaf = pnode;
	    if (ldebug)
		fprintf(stderr,"FinishTree: Making %p the head\n", pnode);
	} else {
	    pdc->lastleaf->nextleaf = pnode;
	    pdc->lastleaf = pnode;
	    if (ldebug)
		fprintf(stderr,"FinishTree: Making %p the tail\n", pnode);
	}
	return;
    }

    /* recurse down all branches */
    for (i=0; i < CARDINALITY; ++i) {
	FinishTreeRecurse(pdc, pnode->un.down[i], prefix*CARDINALITY+i, depth-1);
    }
}


static void
PrintLeafList(
    struct dyn_counter *ptree)
{
    struct node *pnode = ptree->firstleaf;
    
    fprintf(stderr,"Leaf Linked List...\n");
    while(pnode) {
	fprintf(stderr,"   pnode:%p  prefix:%lu\n", pnode, pnode->prefix);
	pnode = pnode->nextleaf;
    }
}



static struct node *
NextCounterRecurse(
    struct node *node,
    u_long nextix,
    u_long *pix,
    u_long *pcount)
{
    int i;

    if (ldebug)
	fprintf(stderr,"NextCounterRecurse(%p,%lu,%lu,%lu) called\n",
		node, nextix, *pix, *pcount);

    /* base case, NULL */
    if (node == NULL)
	return(NULL);
    

    /* first, check the rest of THIS leaf node */
    for (i=nextix; i < CARDINALITY; ++i) {
	if (node->un.value[i] != 0) {
	    *pix = node->prefix*CARDINALITY+i;
	    *pcount = node->un.value[i];
	    return(node);
	}
    }

    /* check each counter in the NEXT leaf */
    return(NextCounterRecurse(node->nextleaf, 0, pix, pcount));
}


/* internal counter access routine */
static void
MakeCounter(
    struct dyn_counter **ppdc,
    u_long ix,
    u_long val,
    u_long granularity,
    char is_set) /* "set" as opposed to "add" */
{
    u_long *pcounter;

    /* if the counter tree doesn't exist yet, create it */
    if (*ppdc == NULL) {
	*ppdc = MakeCounterStruct();
    }

    /* check granularity */
    if ((*ppdc)->gran == 0) {
	(*ppdc)->gran = granularity;
    } else {
	/* error check */
	if ((*ppdc)->gran != granularity) {
	    fprintf(stderr,"DYNCOUNTER: internal error, granularity changed\n");
	    exit(-1);
	}
    }

    /* find/create the counter */
    pcounter = FindCounter(ppdc, ix, 1);

    /* add or set */
    if (is_set) {
	/* counter = val */
	*pcounter = val;
    } else {
	/* counter += val */
	*pcounter += val;
	(*ppdc)->total_count += val;
    }


    /* check MAX counter value */
    if (*pcounter > (*ppdc)->maxcount)
	(*ppdc)->maxcount = *pcounter;

    return;
}
