%{
/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
 *	Ohio University.
 *
 * ---
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
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		http://www.tcptrace.org/
 *		ostermann@cs.ohiou.edu
 */


#include <stdio.h>
#include <stdarg.h>

#include "tcptrace.h"
#include "filter.h"

#define YYDEBUG 1


%}



%union	{ /* the types that we use in the tokens */
    char *string;
    long signed_long;
    u_long unsigned_long;
    ipaddr *pipaddr;
    Bool bool;
    enum optype op;
    struct filter_node *pf;
}



%token EOS
%token LPAREN RPAREN
%token GREATER GREATER_EQ LESS LESS_EQ EQUAL NEQUAL
%token NOT

/* AND or OR group left to right, NOT is highest precedence, then OR */
%left NOT
%left AND
%left OR

/* BITWISE AND and OR */
%left BAND BOR

/* PLUS and MINUS group left to right, lower prec then TIMES and DIVIDE */
%left PLUS MINUS
%left TIMES DIVIDE MOD

%token <string> VARIABLE STRING
%token <signed_long> SIGNED
%token <unsigned_long> UNSIGNED
%token <bool> BOOL
%token <pipaddr> IPADDR
%type <op> relop
%type <pf> expr leaf number



%% 	/* beginning of the parsing rules	*/
line	: expr EOS
		{InstallFilter($1);}
	;

/* top-level booleans and etc */
expr	: expr AND expr
		{ $$ = MakeBinaryNode(OP_AND,$1,$3);}
	| expr OR expr
		{ $$ = MakeBinaryNode(OP_OR,$1,$3);}
	| NOT expr
		{ $$ = MakeUnaryNode(OP_NOT,$2); }
	| number relop number
		{ $$ = MakeBinaryNode($2,$1,$3);}
	| number
		{ $$ = $1; }
	;


/* numbers are leaves or math operations thereon */
number	: number PLUS number
		{ $$ = MakeBinaryNode(OP_PLUS,$1,$3);}
	| number MINUS number
		{ $$ = MakeBinaryNode(OP_MINUS,$1,$3);}
	| number TIMES number
		{ $$ = MakeBinaryNode(OP_TIMES,$1,$3);}
	| number DIVIDE number
		{ $$ = MakeBinaryNode(OP_DIVIDE,$1,$3);}
	| number MOD number
		{ $$ = MakeBinaryNode(OP_MOD,$1,$3);}
	| number BAND number
		{ $$ = MakeBinaryNode(OP_BAND,$1,$3);}
	| number BOR number
		{ $$ = MakeBinaryNode(OP_BOR,$1,$3);}
	| LPAREN expr RPAREN
		{ $$ = $2; }
	| leaf
		{ $$ = $1; }
	;

/* leaves are constants or variables */
leaf	: VARIABLE
		{ $$ = MakeVarNode($1); }
	| SIGNED
		{ $$ = MakeSignedConstNode($1); }
	| UNSIGNED
		{ $$ = MakeUnsignedConstNode($1); }
	| STRING
		{ $$ = MakeStringConstNode($1); }
	| BOOL
		{ $$ = MakeBoolConstNode($1); }
	| IPADDR
		/* just pretend, for now */
		{ $$ = MakeIPaddrConstNode($1); }
	;

/* relational operators */
relop	: GREATER
		{ $$ = OP_GREATER;}
	| GREATER_EQ
		{ $$ = OP_GREATER_EQ;}
	| LESS
		{ $$ = OP_LESS;}
	| LESS_EQ
		{ $$ = OP_LESS_EQ;}
	| EQUAL
		{ $$ = OP_EQUAL;}
	| NEQUAL
		{ $$ = OP_NEQUAL;}
	;
%%

void
filtyyerror(char *error_string, ...)
{
    fprintf(stderr,"Bad filter expr: '%s'\n", error_string);
}
