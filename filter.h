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
#ifdef HAVE_LONG_LONG
    V_ULLONG,V_LLONG,
#endif /* HAVE_LONG_LONG */
    V_ULONG,V_LONG,
    V_UINT,V_INT,
    V_USHORT,V_SHORT,
    V_UCHAR,V_CHAR,
    V_FLOAT,V_BOOL,V_STRING};




struct var_node {
    Bool isconstant;		/* variable or constant */
    enum vartype vartype;
    union {
	/* for constants */
	union {
	    u_long	u_longint;
	    long	longint;
	    float	floating;
	    Bool	bool;
	    char	*string;
	} unType;
	/* for variables */
	struct {
	    char 	*name;
	    u_int	offset;
	} vardet;
    } unIsConst;
};

struct filter_node {
    int op;
    union {
	struct filter_node_leaf {
	    struct var_node *pvarl;
	    struct var_node *pvarr;
	} leaf;
	struct filter_node_bool {
	    struct filter_node *left;
	    struct filter_node *right;
	} bool;
    } un;
};




/* just a big table of things that we can filter on */
struct filter_line {
    char	*varname;	/* name of the variable to match */
    enum vartype vartype;	/* type of the variable */
    void 	*cl_addr;	/* address when in client */
    void 	*sv_addr;	/* address when in server */
};



/* filter globals */
extern int yyfdebug;


/* externals */
int yyflex(void);
int yyfparse(void);
struct filter_node *MakeFilterNode(int op);
struct var_node *MakeVarNode(enum vartype vartype, Bool fconstant);
struct var_node *LookupVar(char *varname, Bool fclient);
void InstallFilter(struct filter_node *root);
int filter_getc(void *in_junk);
void PrintFilter(struct filter_node *pn);

