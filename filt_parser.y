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
    float floating;
    int op;
    struct filter_node *pf;
    struct var_node *pv;
}



%token LPAREN RPAREN
%token GREATER GREATER_EQ LESS LESS_EQ EQUAL NEQUAL
%token AND OR NOT
%token <string> VARIABLE
%token <string> STRING
%token <signed_long> SIGNED
%token <unsigned_long> UNSIGNED
%token <bool> BOOL
%token <floating> FLOAT
%type <pf> bigbool term expr
%type <op> relop
%type <pv> ref variable


%% 	/* beginning of the parsing rules	*/
line	: bigbool
		{InstallFilter($1);}
	;

bigbool	: term
		{ $$ = $1; }
	| NOT bigbool
		{ $$ = MakeFilterNode(NOT);
		  $$->un.bool.left = $2;
		  $$->un.bool.right = NULL;
		}
	| term AND bigbool
		{ $$ = MakeFilterNode(AND);
		  $$->un.bool.left = $1;
		  $$->un.bool.right = $3;
		}
	| term OR bigbool
		{ $$ = MakeFilterNode(OR);
		  $$->un.bool.left = $1;
		  $$->un.bool.right = $3;
		}
	;

term	: LPAREN bigbool RPAREN
		{ $$ = $2; }
	| expr
		{ $$ = $1; }
	;

expr	: ref relop ref
		{
		    $$ = MakeFilterNode($2);
		    $$->un.leaf.pvarl = $1;
		    $$->un.leaf.pvarr = $3;

		    /* quick check, left side MUST be variable */
		    if ($1->isconstant) {
			fprintf(stderr, "\
Left hand side of relational op must be a constant.\n\
You asked for:\n\t");
			PrintFilter($$);
			printf("\n");
			exit(-1);
		    }

		    /* boolean sanity check, only equality and
		       inequality are legal */
		    if ($1->vartype == V_BOOL) {
			if (($2 != EQUAL) && ($2 != NEQUAL)) {
			    fprintf(stderr, "\
Only equality and inequality testing allowed against boolean type '%s'\n",
				    $1->unIsConst.vardet.name);
			    exit(-1);
			}
		    }
		}
	;

ref	: variable
		{ $$ = $1; }
	| SIGNED
		{ $$ = MakeVarNode(V_LONG,1);
		  $$->unIsConst.unType.longint = $1;}
	| UNSIGNED
		{ $$ = MakeVarNode(V_ULONG,1);
		  $$->unIsConst.unType.u_longint = $1;}
	| STRING
		{ $$ = MakeVarNode(V_STRING,1);
		  $$->unIsConst.unType.string = $1;}
	| BOOL
		{ $$ = MakeVarNode(V_BOOL,1);
		  $$->unIsConst.unType.bool = $1;}
	| FLOAT
		{ $$ = MakeVarNode(V_ULONG,1);
		  $$->unIsConst.unType.floating = $1;}
	;

variable: VARIABLE
		{
		    char vname[100];
		    
		    if (strncasecmp($1,"c_",2) == 0) {
			/* they just asked for the client side */
			$$ = LookupVar($1+2,TRUE);
		    } else if (strncasecmp($1,"s_",2) == 0) {
			/* they just asked for the client side */
			$$ = LookupVar($1+2,FALSE);
		    } else {
			fprintf(stderr,
				"wildcard on '%s' not implemented\n",
				$1);
			exit(-1);
		    }
		}
	;


relop	: GREATER
		{ $$ = GREATER;}
	| GREATER_EQ
		{ $$ = GREATER_EQ;}
	| LESS
		{ $$ = LESS;}
	| LESS_EQ
		{ $$ = LESS_EQ;}
	| EQUAL
		{ $$ = EQUAL;}
	| NEQUAL
		{ $$ = NEQUAL;}
	| NOT
		{ $$ = NOT;}
    	;

%%

void
yyerror(char *error_string, ...)
{
    fprintf(stderr,"Bad filter expr: '%s'\n", error_string);
}
