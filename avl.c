/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
 *      Ohio University.
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
 * Author:      Ramani Yellapragada
 *              School of Electrical Engineering and Computer Science
 *              Ohio University
 *              Athens, OH
 *              http://www.tcptrace.org/
 */
static char const copyright[] =
    "@(#)Copyright (c) 2001 -- Ohio University.\n";
static char const rcsid[] =
    "@(#)$Header$";

#include "tcptrace.h"

/* Local routines for handling AVL tree balancing after inserting a node */
 
static void SnapRotLeft(ptp_snap **n);
static void SnapRotRight(ptp_snap **n);
static enum AVLRES SnapLeftGrown(ptp_snap **n);
static enum AVLRES SnapRightGrown(ptp_snap **n);
 
/* Local routines for handling AVL tree balancing after removing a node */
 
static enum AVLRES SnapLeftShrunk(ptp_snap **n);
static enum AVLRES SnapRightShrunk(ptp_snap **n);
static int SnapFindHighest(ptp_snap *target, ptp_snap **n, enum AVLRES *res);
static int SnapFindLowest(ptp_snap *target, ptp_snap **n, enum AVLRES *res);

/*
 * SnapRotLeft - perform counter clockwise rotation
 */

static void 
SnapRotLeft(
	    ptp_snap **n)
{
   ptp_snap *tmp = *n;

   if (debug > 4)
     printf("SnapRotLeft(): Rotating the AVL tree counter clockwise\n");
   
   *n = (*n)->right;
   tmp->right = (*n)->left;
   (*n)->left = tmp;
}

/*
 * SnapRotRight - perform clockwise rotation
 */

static void 
SnapRotRight(
	     ptp_snap **n)
{
   ptp_snap *tmp = *n;
   
   if (debug > 4)
     printf("SnapRotRight(): Rotating the AVL tree clockwise\n");
   
   *n = (*n)->left;
   tmp->left = (*n)->right;
   (*n)->right = tmp;
}

/* SnapLeftGrown - For balancing an AVL tree after insertion
 * Input is the address of a node. The node's left subtree has grown 
 * due to insertion. 
 */

static enum AVLRES 
SnapLeftGrown(
	      ptp_snap **n)
{
   if (debug > 4)
     printf("SnapLeftGrown(): Balancing the AVL tree because left subtree\
             has grown after insertion\n");
   
   switch ((*n)->skew) {
    case LEFT:
      if ((*n)->left->skew == LEFT) {
	 (*n)->skew = (*n)->left->skew = EQUAL1;
	 SnapRotRight(n);
      }
      else {
	 switch ((*n)->left->right->skew) {
	  case LEFT:
	    (*n)->skew = RIGHT;
	    (*n)->left->skew = EQUAL1;
	    break;
	  case RIGHT:
	    (*n)->skew = EQUAL1;
	    (*n)->left->skew = LEFT;
	    break;
	  default:
	    (*n)->skew = EQUAL1;
	    (*n)->left->skew = EQUAL1;
	 }
	 
	 (*n)->left->right->skew = EQUAL1;
	 SnapRotLeft(&(*n)->left);
	 SnapRotRight(n);
      }
      return OK;
      
    case RIGHT:
      (*n)->skew = EQUAL1;
      return OK;
      
    default:
      (*n)->skew = LEFT;
      return BALANCE;
   }
}

/* SnapRightGrown - For balancing an AVL tree after insertion
 * Input is the address of a node. The node's right subtree has grown
 * due to insertion.
 */

static enum AVLRES 
SnapRightGrown(
	       ptp_snap **n)
{
   if (debug > 4)
     printf("SnapRightGrown(): Balancing the AVL tree because right subtree\
             has grown after insertion\n");
   
   switch ((*n)->skew) {
    case LEFT:
      (*n)->skew = EQUAL1;
      return OK;
      
    case RIGHT:
      if ((*n)->right->skew == RIGHT) {
	 (*n)->skew = (*n)->right->skew = EQUAL1;
	 SnapRotLeft(n);
      }
      else {
	 switch ((*n)->right->left->skew) {
	  case RIGHT:
	    (*n)->skew = LEFT;
	    (*n)->right->skew = EQUAL1;
	    break;
	    
	  case LEFT:
	    (*n)->skew = EQUAL1;
	    (*n)->right->skew = RIGHT;
	    break;
	    
	  default:
	    (*n)->skew = EQUAL1;
	    (*n)->right->skew = EQUAL1;
	 }
	 
	 (*n)->right->left->skew = EQUAL1;
	 SnapRotRight(&(*n)->right);
	 SnapRotLeft(n);
      }
      return OK;
      
    default:
      (*n)->skew = RIGHT;
      return BALANCE;
   }
}

/*
 * SnapInsert - insert a node into the AVL tree
 * and balance the AVL tree
 */

enum AVLRES 
SnapInsert(
	   ptp_snap **root, 
	   ptp_snap *new_node)
{
   enum AVLRES tmp;
   int dir;
   
   if (debug > 4)
     printf("SnapInsert(): Inserting a node in the AVL tree\n");
   
   if (!(*root)) {	
      *root = new_node;	
      (*root)->left = (*root)->right = NULL;
      (*root)->skew = EQUAL1;
      return BALANCE;
   }
   
   else if (AVL_CheckHash(&new_node->addr_pair, &((*root)->addr_pair), &dir) == LOW) {
      if ((tmp = SnapInsert(&(*root)->left, new_node)) == BALANCE) {
	 return SnapLeftGrown(root);
      }
      return tmp;
   }
   
   else if (AVL_CheckHash(&new_node->addr_pair, &((*root)->addr_pair), &dir) == HIGH) {
      if ((tmp = SnapInsert(&(*root)->right, new_node)) == BALANCE) {
	 return SnapRightGrown(root);
      }
      return tmp;
   }  
   return 0;
}

/*
 * SnapLeftShrunk - For balancing an AVL tree after removing a node
 * Input is the address of a node. The node's left subtree has shrunk
 * due to removal and might have made the tree unbalanced.
 */

static enum AVLRES 
SnapLeftShrunk(
	       ptp_snap **n)
{
   if (debug > 4)
     printf("SnapLeftshrunk(): Balancing the AVL tree because left subtree\
             has shrunk after removal\n");
   
   switch ((*n)->skew) {
    case LEFT:
      (*n)->skew = EQUAL1;
      return BALANCE;
      
    case RIGHT:
      if ((*n)->right->skew == RIGHT) {
	 (*n)->skew = (*n)->right->skew = EQUAL1;
	 SnapRotLeft(n);
	 return BALANCE;
      }
      
      else if ((*n)->right->skew == EQUAL1) {
	 (*n)->skew = RIGHT;
	 (*n)->right->skew = LEFT;
	 SnapRotLeft(n);
	 return OK;
      }
      
      else {
	 switch ((*n)->right->left->skew) {
	  case LEFT:
	    (*n)->skew = EQUAL1;
	    (*n)->right->skew = RIGHT;
	    break;
	    
	  case RIGHT:
	    (*n)->skew = LEFT;
	    (*n)->right->skew = EQUAL1;
	    break;
	    
	  default:
	    (*n)->skew = EQUAL1;
	    (*n)->right->skew = EQUAL1;
	 }
	 
	 (*n)->right->left->skew = EQUAL1;
	 SnapRotRight(& (*n)->right);
	 SnapRotLeft(n);
	 return BALANCE;
      }
      
    default:
      (*n)->skew = RIGHT;
      return OK;
   }  
}

/*
 * SnapRightShrunk - For balancing an AVL tree after removing a node
 * Input is the address of a node. The node's right subtree has shrunk
 * due to removal and might have made the tree unbalanced.
 */

static enum AVLRES 
SnapRightShrunk(
		ptp_snap **n)
{
   if (debug > 4)
     printf("SnapRightShrunk(): Balancing the AVL tree because right subtree\
             has shrunk after removal\n");
   
   switch ((*n)->skew) {
    case RIGHT:
      (*n)->skew = EQUAL1;
      return BALANCE;
      
    case LEFT:
      if ((*n)->left->skew == LEFT) {
	 (*n)->skew = (*n)->left->skew = EQUAL1;
	 SnapRotRight(n);
	 return BALANCE;
      }
      else if ((*n)->left->skew == EQUAL1) {
	 (*n)->skew = LEFT;
	 (*n)->left->skew = RIGHT;
	 SnapRotRight(n);
	 return OK;
      }
      
      else {
	 switch ((*n)->left->right->skew) {
	  case LEFT:
	    (*n)->skew = RIGHT;
	    (*n)->left->skew = EQUAL1;
	    break;
	    
	  case RIGHT:
	    (*n)->skew = EQUAL1;
	    (*n)->left->skew = LEFT;
	    break;
	    
	  default:
	    (*n)->skew = EQUAL1;
	    (*n)->left->skew = EQUAL1;
	 }
	 
	 (*n)->left->right->skew = EQUAL1;
	 SnapRotLeft(& (*n)->left);
	 SnapRotRight(n);
	 return BALANCE;
      }
      
    default:
      (*n)->skew = LEFT;
      return OK;
   }
}

/*
 * SnapFindHighest - replace a node with a subtree's highest-ranking item
 */

static int 
SnapFindHighest(
		ptp_snap *target, 
		ptp_snap **n, 
		enum AVLRES *res)
{
   ptp_snap *tmp;
   
   if (debug > 4)
     printf("SnapFindHighest(): Replacing a node with a subtree's\
             highest ranking item \n");
   
   *res = BALANCE;
   if (! (*n)) {
      return 0;
   }
   
   if ((*n)->right) {
      if (!SnapFindHighest(target, & (*n)->right, res)) {
	 return 0;
      }
      
      if (*res == BALANCE) {
	 *res = SnapRightShrunk(n);
      }
      
      return 1;
   }
   
   target->addr_pair  = (*n)->addr_pair;
   target->ptp = (*n)->ptp;
   tmp = *n;
   (*n) = (*n)->left;
   return 1;
}

/*
 * SnapFindLowest - replace a node with a subtree's lowest-ranking item
 */

static int 
  SnapFindLowest(
		 ptp_snap *target, 
		 ptp_snap **n, 
		 enum AVLRES *res)
{
   ptp_snap *tmp;
   
   if (debug > 4)
     printf("SnapFindLowest(): Replacing a node with a subtree's\
             lowest ranking item \n");
   
   *res = BALANCE;
   if (!(*n)) {
      return 0;
   }
   
   if ((*n)->left) {
      if (!SnapFindLowest(target, & (*n)->left, res)) {
	 return 0;
      }
      
      if (*res == BALANCE) {
	 *res =  SnapLeftShrunk(n);
      }
      
      return 1;
   }
   
   target->addr_pair = (*n)->addr_pair;
   target->ptp = (*n)->ptp;
   tmp = *n;
   *n = (*n)->right;
   return 1;
}

/*
 * SnapRemove - remove a node from the AVL tree
 * and balance the AVL tree
 */

enum AVLRES 
SnapRemove(
	   ptp_snap **root, 
	   tcp_pair_addrblock addr)
{   
   enum AVLRES tmp = BALANCE;
   int dir;
   
   if (debug > 4)
     printf("SnapRemove(): Removing a node from the AVL tree\n");
   
   if (!(*root)) {
      return 0;
   }
   
   if (AVL_CheckHash(&addr, &((*root)->addr_pair), &dir) == LOW) {
      if ((tmp = SnapRemove(&(*root)->left, addr)) == BALANCE) {
	 return SnapLeftShrunk(root);
      }
      
      return tmp;
   }
   
   if (AVL_CheckHash(&addr, &((*root)->addr_pair), &dir) == HIGH) {
      if ((tmp = SnapRemove(&(*root)->right, addr)) == BALANCE) {
	 return SnapRightShrunk(root);
      }
      
      return tmp;
   }
   
   if ((*root)->left) {
      if (SnapFindHighest(*root, &((*root)->left), &tmp)) {
	 if (tmp == BALANCE) {
	    tmp = SnapLeftShrunk(root);
	 }
	 return tmp;
      }
   }
   
   if ((*root)->right) {
      if (SnapFindLowest(*root, &((*root)->right), &tmp)) {
	 if (tmp == BALANCE) {
	    tmp = SnapRightShrunk(root);
	 }
	 return tmp;
      }
   }
   
   *root = NULL;
   return BALANCE;
}
