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
 * Author:	Marina Bykova
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header$";


/*#include <stdlib.h>*/
#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "pool.h"

#ifndef _BASIC_POOL_H
#define _BASIC_POOL_H

struct Block {
  struct Block	*next;
};

struct Pool {
  unsigned int	block_size;	/* size of a memory block */
  unsigned int	block_no;	/* number of block in the pool */
  struct Block	*list;		/* pointer to a list of free blocks */
  short		sorted;		/* whether list of blocks should be sorted */
};

#define DFLT_POOLS_NUM		10	/* default number of pools */
#define DFLT_BLOCKS_NUM		16	/* default number of blocks 
					   in free list */
#define RESIZE_TIMES 2		/* by how many times we need to increase table
				 * size for each memory pool */

/* global variables */
static struct Pool	*pools = NULL;	/* table of memory pools */
static unsigned		table_size = 0;	/* size of the pool table */
static int		pool_num = 0;	/* number of existing memory pools */

/* local routines */
static void *PoolValloc(const int, const unsigned, unsigned *);
static struct Block *MakeList(const int, void *, const unsigned);
static int PoolRealloc(const int, const unsigned);
static void PoolInsertList(const int, struct Block *);


/*
 * MakeMemPool	- given a block size, create a new memory pool for 
 *		such blocks of memory. Returns pool number or -1 
 *		in case an error occures. 
 *		NOTE: pool numbers start with 0, so that zero pool number
 *		is valid.
 */
int
MakeMemPool(
	    const unsigned bsize, /* block size for a pool */
	    const int sorted)/* if non-zero, tells to sort linked list of 
				free blocks */
{
  void			*buffer = NULL;
  unsigned		buffer_size = 0;
  unsigned		old_table_size = 0;
  struct Pool		*tmp_pools = NULL;	/* a pointer to memory pools */

  if (0) {
    printf("MakeMemPool(%0x) called\n", bsize);
  }

  /* if pool table doesn't exist yet, create it */
  if (pools == NULL) {
    table_size = DFLT_POOLS_NUM;
    pools = (struct Pool *)malloc(sizeof(struct Pool)*table_size);
    if (pools == NULL) {
      fprintf(stderr, "MakeMemPool: cannot allocate memory for pool table: ");
      fprintf(stderr, "malloc failed\n");
      exit(1);
    }
    memset((void *)pools, '\00', sizeof(struct Pool)*table_size);
  }    
  /* if the table exists but we are out of free space in it 
   *  make it bigger 
   */
  else if (table_size == pool_num) {
    old_table_size = table_size;
    table_size = old_table_size * RESIZE_TIMES;
    if ((tmp_pools = (struct Pool *)realloc((void *)pools, 
					    table_size*sizeof(struct Pool))) 
	== NULL) {
      fprintf(stderr, "MakeMemPool: Cannot allocate memory: realloc failed\n");
      exit(1);
    }
    else {
      pools = tmp_pools;
    }
    memset(pools+(old_table_size*sizeof(struct Pool)), '\00', 
	   (table_size-old_table_size)*sizeof(struct Pool));
  }
  pools[pool_num].block_size = bsize;

  buffer = PoolValloc(pool_num, DFLT_BLOCKS_NUM, &buffer_size);
  if (buffer == NULL) {
    fprintf(stderr, "MakeMemPool: Cannot allocate memory: PoolValloc failed\n");
    exit(1);
  }
  pools[pool_num].list = MakeList(pool_num, buffer, buffer_size);

  if (sorted) {
    pools[pool_num].sorted = 1;
  }
  pool_num++;
  return (pool_num - 1);
}

/*
 * PoolMalloc - given by pool id and number of blocks, give a block
 *		of memory for that number of units.
 *		If successful, returns a pointer, or NULL otherwise
 */
void *
PoolMalloc(
	   const int poolid,	/* pool id */
	   const unsigned bytes)/* size of the  block (in bytes) */
{
  unsigned	counter = 0;
  struct Block	*block = NULL;
  struct Block	*next = NULL;
  struct Block	*prev = NULL;
  struct Block	*tmp_prev = NULL;
  void		*buffer = NULL;
  unsigned	buffer_size = 0;
  struct Block	*new_list = NULL;
  unsigned	bnumber;

  if (0) {
    printf("PoolMalloc(%0x, %0x) called.. ", poolid, bytes);
  }

  if ((poolid >= pool_num) || (poolid < 0)) {
    fprintf(stderr, "PoolMalloc: wrong poolid\n");
    exit(1);
  }
  if (bytes == 0) {
    exit(1);
  }

  if ((bytes % pools[poolid].block_size) != 0) {
    /* not a whole number of structures */
    fprintf(stderr, "PoolMalloc: cannot allocate '%i' bytes ", bytes);
    fprintf(stderr, "for this memory pool\n");
    exit(1);
  }
  bnumber = bytes / pools[poolid].block_size;

  if (pools[poolid].block_no < bnumber) {
    if (PoolRealloc(poolid, bnumber) < 0) {
      fprintf(stderr, 
              "PoolMalloc: cannot allocate enough memory, PoolRealloc failed\n");
    }
  }

  if (bnumber > 1) {
    /* search for right place and give that number of blocks */
    block = pools[poolid].list;
    /* go through the linked list of block searching for bnumber of 
     *contigious blocks */
    while ((block != NULL) && (counter != bnumber)) {
      next = block->next;
      /* count number of contigious blocks */
      for (counter = 1; counter < bnumber; counter++) {
	if ((block + pools[poolid].block_size*counter) == next) {
	  tmp_prev = next;
	  next = next->next;
	}
	else {/* the block is not contigious, start over */
	  block = next;
	  prev = tmp_prev;
	  break;
	}
      }
    }
    if (block == NULL) {/* continious bytes  not found */
      /* call valloc for the block */
      buffer = PoolValloc(poolid, bnumber, &buffer_size);
      if (buffer == NULL) {
	fprintf(stderr, "PoolMalloc: Cannot allocate memory: PoolValloc failed\n");
	exit(1);
      }
      new_list = MakeList(poolid, buffer, buffer_size);
      block = new_list;
      /* save needed number of blocks and add the rest to the linked-list
       * of free blocks */
      for (counter = 0; counter < bnumber; counter++) {
	new_list = new_list->next;
      }
      PoolInsertList(poolid, new_list);
    }
    else {/* block of continious memory is found */
      if (block == pools[poolid].list) {
	pools[poolid].list = next;
      }
      else {
	prev->next = next;
      }
    }
    /* reset memory and return the block */
    memset(block, '\00', pools[poolid].block_size*bnumber);
    pools[poolid].block_no -= bnumber;

    return block;
  }
  else {/* only memory for 1 structure is requested */
    /* no need of searching, give the first block in the list */
    block = pools[poolid].list;
    pools[poolid].list = block->next;
    memset(block, '\00', pools[poolid].block_size);
    pools[poolid].block_no--;

    return block;
  }
}


/* 
 * PoolValloc - given a pool number and number of blocks we want to use,
 *		allocate memory at the pagesize boundary for at least that
 *		number of blocks. Returns a buffer of bsize (contents of 
 *		bsize will be rewritten 
 */
static void *
PoolValloc(
	   const int poolid,		/* pool id */
	   const unsigned bnumber,	/* we will get at least bnumber 
					   of blocks */
	   unsigned *bsize)		/* size of the returned buffer */
{
  unsigned	pagesize;
  void		*buffer = NULL;
  unsigned	buffer_size = 0;

  if (0) {
    printf("PoolValloc(%0x, %0x) called\n", poolid, bnumber);
  }

  /* find out how many memory pages we need and allocate such amount 
   *  of memory 
   */
#if defined(PAGESIZE)
  /* there's "supposed" to be a constant... */
  pagesize = PAGESIZE;
#elif defined(_SC_PAGESIZE)
  /* but maybe we can get it from the system... */
  pagesize = sysconf(_SC_PAGESIZE);
#else
  /* if all else fails, just guess 8k, close enough */
  pagesize = 8*1024;
#endif
  buffer_size = (ceil(pools[poolid].block_size * bnumber / 
		      (float)pagesize)) * pagesize;

#ifdef HAVE_VALLOC
  buffer = (void *)valloc(buffer_size);
#else /* HAVE_VALLOC */
#ifdef HAVE_MEMALIGN
  buffer = (void *)memalign(buffer_size, pagesize);
#else /* HAVE_MEMALIGN */
  buffer = (void *)malloc(buffer_size);
#endif /* HAVE_MEMALOGN */
#endif /* HAVE_VALLOC */
  if (buffer == NULL) {
    fprintf(stderr, "PoolValloc: cannot allocate memory: valloc ");
    fprintf(stderr, "(or equivalent function) failed\n");
    exit(1);
  }
  memset(buffer, '\00', buffer_size);

  /* increase number of available blocks for the pool */
  pools[poolid].block_no += floor(buffer_size/(float)pools[poolid].block_size);
  (*bsize) = buffer_size;

  return buffer;
}

/* 
 * MakeList - given by a pool id, buffer, and buffer's size, make a linked 
 *		list of free memory blocks for that pool.
 *		Breaks the buffer into peaces, makes a linked list, and return
 *		pointer to the list.
 */
static struct Block *
MakeList(
	 const int poolid,		/* pool id */
	 void *buffer,			/* a buffer to be restructured */
	 const unsigned buffer_size)	/* the buffer's size */
{
  struct Block	*block = NULL;
  struct Block	*next = NULL;

  if (0) {
    printf("MakeList(%0x, %p, %0x) called\n", poolid, buffer, buffer_size);
  }

  block = (struct Block *)buffer;

  /* make a linked list of free memory blocks */
  do {
    next = (struct Block *)((char *)block + pools[poolid].block_size);
    block->next = next;
    block = next;
  } while ((char *)next <= 
	   ((char *)buffer + buffer_size - (pools[poolid].block_size*2)));
  block->next = NULL;

 return (struct Block *)buffer;
}

/*
 * PoolRealloc - given by a poolid and number of blocks, allocate memory 
 *		on pagesize boundary for at least that number of blocks, 
 *		insert new blocks into the pool's linked list of free blocks.
 *		If successful, returns 0, or -1 otherwise.
 */
static int
PoolRealloc(
	    const int poolid,
	    const unsigned bnumber)
{
  void		*buffer = NULL;
  unsigned	buffer_size;
  struct Block	*new_list = NULL;

  if (0) {
    printf("PoolRealloc(%0x, %0x) called\n", poolid, bnumber);
  }

  /* allocate space first */
  buffer = PoolValloc(poolid, bnumber, &buffer_size);
  if (buffer == NULL) {
    fprintf(stderr, "PoolRealloc: Cannot allocate memory: PoolValloc failed\n");
   exit(1);
  }
  /* build a linked list from the buffer */
  new_list = MakeList(poolid, buffer, buffer_size);

  /* insert the list */
  if (pools[poolid].list == NULL) {
    pools[poolid].list = new_list;
  }
  else {
    PoolInsertList(poolid, new_list);
  }
  return 0;
}

/* 
 * PoolInsertList - given by a pool id and a linked list, insert the list
 *		into the pool's linked list of free blocks.
 */
static void
PoolInsertList(
	       const int poolid,
	       struct Block *new_list)
{
  struct Block	*block = NULL;
  struct Block	*next = NULL;

  if (0) {
    printf("PoolInsertList(%0x, %p) called\n", poolid, new_list);
  }
  if (new_list == NULL) {
    return;
  }
  block = pools[poolid].list;
  
  if (pools[poolid].sorted) {
  /* search for a place to insert new linked list into 
   * the pool's linked list and insert it */
    if (block > new_list) {/* new list is to inserted at the head */
      next = block;
      pools[poolid].list = new_list;
      block = new_list;
    }
    else {/* search for right place for insertion */
      while ((block->next < new_list) &&
	     (block->next != NULL)) {
	block = block->next;
      }
      next = block->next;
      block->next = new_list;
    }
    /* go til the end of the linked-list being inseted and add the rest 
     * of the old linked-list to the end of it */
    for (; block->next != NULL; block = block->next)
      ;
    block->next = next;
  }
  else {/* not sorted */
    /* prepend new linked list to the previous list */
    block = new_list;
    while (block->next)
      block = block->next;
    block->next = pools[poolid].list;
    pools[poolid].list = new_list;
  }
}

/*
 * PoolFree - given by a pool id and a pointer, free that block of memory
 *		from the pool.
 */
void
PoolFree(
	 const int poolid,
	 void *ptr)
{ 
  struct Block	*block;
  struct Block	*b, *n;

  if (0) {
    printf("PoolFree(%0x, %p) called\n", poolid, ptr);
    fflush(stdout);
  }

  /* check poolid first */
  if ((poolid >= pool_num) || (poolid < 0)) {
    return;
  }
  if (!ptr)
    return;

  memset(ptr, '\00', pools[poolid].block_size);
  block = (struct Block *)ptr;

  if (0) { /* this part was used for debugging. slows down dramatically */
    for (b = pools[poolid].list; b; b = b->next) {
      if (b == block) {
	fprintf(stderr, 
		"WARNING! PoolFree(%0x, %p) is called for already freed block of memory\n",
		poolid, ptr);
	return;
      }
    }
  }

  /* linked list for that pool id is empty */
  if (pools[poolid].list == NULL) {
    block->next = NULL;
    pools[poolid].list = block;
    return;
  }

  /* insert block into correct locatioin */
  if (pools[poolid].sorted) {/* sorted linked list */
    if (block < pools[poolid].list) {
      block->next = pools[poolid].list;
      pools[poolid].list = block;
    }
    else {
      b = pools[poolid].list;
      while ((b->next < block) &&
	     (b->next != NULL)) {
	b = b->next;
      }
      /* insert after b */
      n = b->next;
      b->next = block;
      block->next = n;
    }
  }
  else {/* not sorted */
    /* insert into begining of the linked list */
    block->next = pools[poolid].list;
    pools[poolid].list = block;
  }

  pools[poolid].block_no++;
}

#endif
