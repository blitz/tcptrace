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

    /* functions */
    V_FUNC	=13,		/* function returning unsigned */
    V_UFUNC	=14,		/* function returning signed */
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
};


/* Constant -- just a big union based on the type */
union Constant {
    u_llong	u_longint;
    llong	longint;
    Bool	bool;
    char	*string;
};

/* Variable - keep the name and offset within a tcp_pair */
struct Variable {
    char 	*name;
    u_int	offset;
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
extern int yyfdebug;


/* externals */
int yyflex(void);
int yyfparse(void);
void InstallFilter(struct filter_node *root);
int filter_getc(void *in_junk);
void PrintFilter(struct filter_node *pn);
char *Filter2Str(struct filter_node *pn);

struct filter_node *MakeUnaryNode(enum optype op, struct filter_node *pf);
struct filter_node *MakeBinaryNode(enum optype op, struct filter_node *pf_left, struct filter_node *pf_right);
struct filter_node *MakeVarNode(char *varname);
struct filter_node *MakeStringConstNode(char *val);
struct filter_node *MakeBoolConstNode(Bool val);
struct filter_node *MakeSignedConstNode(llong val);
struct filter_node *MakeUnsignedConstNode(u_llong val);

/* functions for calculated values */
u_llong VFuncClntTput(tcp_pair *ptp);
u_llong VFuncServTput(tcp_pair *ptp);



