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
static char const GCC_UNUSED rcsid_filter[] =
    "@(#)$Header$";


/* all of the variable types that we understand */
enum vartype {
    V_ULONG	= 1,
    V_LONG	= 2,
    V_UINT	= 3,
    V_INT	= 4,
    V_USHORT	= 5,
    V_SHORT	= 6,
    V_UCHAR	= 7,
    V_CHAR	= 8,
    V_BOOL	= 9,
    V_STRING	= 10,
    V_ULLONG	= 11,
    V_LLONG	= 12,
    V_IPADDR	= 13,

    /* functions */
    V_FUNC	=14,		/* function returning unsigned */
    V_UFUNC	=15		/* function returning signed */
};



/* all of the operations that we understand */
enum optype {
    /* just a constant */
    OP_CONSTANT	  = 101,

    /* a variable */
    OP_VARIABLE	  = 102,

    /* BINARY OPs */
    OP_AND	  = 103,
    OP_OR	  = 104,
    OP_EQUAL	  = 105,
    OP_NEQUAL	  = 106,
    OP_GREATER	  = 107,
    OP_GREATER_EQ = 108,
    OP_LESS	  = 109,
    OP_LESS_EQ	  = 110,

    /* Unary OPs */
    OP_NOT	  = 111,
    OP_SIGNED	  = 112,	/* convert unsigned to signed */

    /* binary arithmetic */
    OP_PLUS	  = 113,
    OP_MINUS	  = 114,
    OP_TIMES	  = 115,
    OP_DIVIDE	  = 116,
    OP_MOD	  = 117,

    /* bitwise arithmetic */
    OP_BAND	  = 118,
    OP_BOR	  = 119
};


/* Constant -- just a big union based on the type */
union Constant {
    u_llong	u_longint;
    llong	longint;
    Bool	bool;
    char	*string;
    ipaddr	*pipaddr;
};

/* Variable - keep the name and offset within a tcp_pair */
struct Variable {
    char 	*name;
    u_long 	offset;
    Bool	fclient;	/* from the client or server side? */
    enum vartype realtype;
};

/* Binary - binary operation */
struct Binary {
    struct filter_node *left;
    struct filter_node *right;
};

/* Unary - unary operations */
struct Unary {
    struct filter_node *pf;
};


struct filter_node {
    enum optype op;		/* node type */
    enum vartype vartype;	/* type of the result */
    union {
	struct Unary unary;
	struct Binary binary;
	struct Variable variable;
	union Constant constant;
    } un;
    Bool conjunction;
    struct filter_node *next_var; /* for wildcard variable matches */
};


/* the result of executing a filter node */
struct filter_res {
    enum vartype vartype;
    union Constant val;
};


/* just a big table of things that we can filter on */
struct filter_line {
    char	*varname;	/* name of the variable to match */
    enum vartype vartype;	/* type of the variable */
    void 	*cl_addr;	/* address when in client */
    void 	*sv_addr;	/* address when in server */
    char	*descr;		/* brief description */
};



/* filter globals */
extern int filtyydebug;


/* externals */
int filtyylex(void);
int filtyyparse(void);
void filtyyerror(char *error_string, ...);
void InstallFilter(struct filter_node *root);
int filter_getc();
void PrintFilter(struct filter_node *pn);
char *Filter2Str(struct filter_node *pn);

struct filter_node *MakeUnaryNode(enum optype op, struct filter_node *pf);
struct filter_node *MakeBinaryNode(enum optype op, struct filter_node *pf_left, struct filter_node *pf_right);
struct filter_node *MakeVarNode(char *varname);
struct filter_node *MakeStringConstNode(char *val);
struct filter_node *MakeBoolConstNode(Bool val);
struct filter_node *MakeSignedConstNode(llong val);
struct filter_node *MakeUnsignedConstNode(u_llong val);
struct filter_node *MakeIPaddrConstNode(ipaddr *pipaddr);

/* functions for calculated values */
u_llong VFuncClntTput(tcp_pair *ptp);
u_llong VFuncServTput(tcp_pair *ptp);



