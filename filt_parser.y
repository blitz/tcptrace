%{
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
