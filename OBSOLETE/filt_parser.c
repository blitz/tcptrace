
# line 2 "filt_parser.y"
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



# line 44 "filt_parser.y"
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
	{ /* the types that we use in the tokens */
    char *string;
    long signed_long;
    u_long unsigned_long;
    Bool bool;
    float floating;
    enum optype op;
    struct filter_node *pf;
    struct var_node *pv;
} YYSTYPE;
# define LPAREN 257
# define RPAREN 258
# define GREATER 259
# define GREATER_EQ 260
# define LESS 261
# define LESS_EQ 262
# define EQUAL 263
# define NEQUAL 264
# define AND 265
# define OR 266
# define NOT 267
# define VARIABLE 268
# define STRING 269
# define SIGNED 270
# define UNSIGNED 271
# define BOOL 272
# define FLOAT 273

#ifdef __STDC__
#include <stdlib.h>
#include <string.h>
#else
#include <malloc.h>
#include <memory.h>
#endif

#include <values.h>

#ifdef __cplusplus

#ifndef yyferror
	void yyferror(const char *);
#endif

#ifndef yyflex
#ifdef __EXTERN_C__
	extern "C" { int yyflex(void); }
#else
	int yyflex(void);
#endif
#endif
	int yyfparse(void);

#endif
#define yyfclearin yyfchar = -1
#define yyferrok yyferrflag = 0
extern int yyfchar;
extern int yyferrflag;
YYSTYPE yyflval;
YYSTYPE yyfval;
typedef int yyftabelem;
#ifndef YYMAXDEPTH
#define YYMAXDEPTH 150
#endif
#if YYMAXDEPTH > 0
int yyf_yyfs[YYMAXDEPTH], *yyfs = yyf_yyfs;
YYSTYPE yyf_yyfv[YYMAXDEPTH], *yyfv = yyf_yyfv;
#else	/* user does initial allocation */
int *yyfs;
YYSTYPE *yyfv;
#endif
static int yyfmaxdepth = YYMAXDEPTH;
# define YYERRCODE 256

# line 123 "filt_parser.y"


void
yyferror(char *error_string, ...)
{
    fprintf(stderr,"Bad filter expr: '%s'\n", error_string);
}
yyftabelem yyfexca[] ={
-1, 1,
	0, -1,
	-2, 0,
	};
# define YYNPROD 21
# define YYLAST 39
yyftabelem yyfact[]={

     5,     8,    11,     9,    10,    12,    13,    14,    27,     7,
     4,     8,    11,     9,    10,    12,    18,    19,    20,    21,
    22,    23,     1,     2,    24,    17,     6,    28,    15,    16,
     3,     0,     0,     0,     0,     0,     0,    25,    26 };
yyftabelem yyfpact[]={

  -257,-10000000,-10000000,  -259,  -257,  -257,-10000000,  -243,-10000000,-10000000,
-10000000,-10000000,-10000000,  -257,  -257,-10000000,  -250,  -267,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000 };
yyftabelem yyfpgo[]={

     0,    23,    30,    26,     9,    25,    22 };
yyftabelem yyfr1[]={

     0,     6,     1,     1,     1,     1,     2,     2,     3,     4,
     4,     4,     4,     4,     5,     5,     5,     5,     5,     5,
     5 };
yyftabelem yyfr2[]={

     0,     3,     3,     5,     7,     7,     7,     3,     7,     3,
     3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
     3 };
yyftabelem yyfchk[]={

-10000000,    -6,    -1,    -2,   267,   257,    -3,    -4,   268,   270,
   271,   269,   272,   265,   266,    -1,    -1,    -5,   259,   260,
   261,   262,   263,   264,   267,    -1,    -1,   258,    -4 };
yyftabelem yyfdef[]={

     0,    -2,     1,     2,     0,     0,     7,     0,     9,    10,
    11,    12,    13,     0,     0,     3,     0,     0,    14,    15,
    16,    17,    18,    19,    20,     4,     5,     6,     8 };
typedef struct
#ifdef __cplusplus
	yyftoktype
#endif
{ char *t_name; int t_val; } yyftoktype;
#ifndef YYDEBUG
#	define YYDEBUG	0	/* don't allow debugging */
#endif

#if YYDEBUG

yyftoktype yyftoks[] =
{
	"LPAREN",	257,
	"RPAREN",	258,
	"GREATER",	259,
	"GREATER_EQ",	260,
	"LESS",	261,
	"LESS_EQ",	262,
	"EQUAL",	263,
	"NEQUAL",	264,
	"AND",	265,
	"OR",	266,
	"NOT",	267,
	"VARIABLE",	268,
	"STRING",	269,
	"SIGNED",	270,
	"UNSIGNED",	271,
	"BOOL",	272,
	"FLOAT",	273,
	"-unknown-",	-1	/* ends search */
};

char * yyfreds[] =
{
	"-no such reduction-",
	"line : bigbool",
	"bigbool : term",
	"bigbool : NOT bigbool",
	"bigbool : term AND bigbool",
	"bigbool : term OR bigbool",
	"term : LPAREN bigbool RPAREN",
	"term : expr",
	"expr : ref relop ref",
	"ref : VARIABLE",
	"ref : SIGNED",
	"ref : UNSIGNED",
	"ref : STRING",
	"ref : BOOL",
	"relop : GREATER",
	"relop : GREATER_EQ",
	"relop : LESS",
	"relop : LESS_EQ",
	"relop : EQUAL",
	"relop : NEQUAL",
	"relop : NOT",
};
#endif /* YYDEBUG */
# line	1 "/usr/ccs/bin/yaccpar"
/*
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#pragma ident	"@(#)yaccpar	6.12	93/06/07 SMI"

/*
** Skeleton parser driver for yacc output
*/

/*
** yacc user known macros and defines
*/
#define YYERROR		goto yyferrlab
#define YYACCEPT	return(0)
#define YYABORT		return(1)
#define YYBACKUP( newtoken, newvalue )\
{\
	if ( yyfchar >= 0 || ( yyfr2[ yyftmp ] >> 1 ) != 1 )\
	{\
		yyferror( "syntax error - cannot backup" );\
		goto yyferrlab;\
	}\
	yyfchar = newtoken;\
	yyfstate = *yyfps;\
	yyflval = newvalue;\
	goto yyfnewstate;\
}
#define YYRECOVERING()	(!!yyferrflag)
#define YYNEW(type)	malloc(sizeof(type) * yyfnewmax)
#define YYCOPY(to, from, type) \
	(type *) memcpy(to, (char *) from, yyfnewmax * sizeof(type))
#define YYENLARGE( from, type) \
	(type *) realloc((char *) from, yyfnewmax * sizeof(type))
#ifndef YYDEBUG
#	define YYDEBUG	1	/* make debugging available */
#endif

/*
** user known globals
*/
int yyfdebug;			/* set to 1 to get debugging */

/*
** driver internal defines
*/
#define YYFLAG		(-10000000)

/*
** global variables used by the parser
*/
YYSTYPE *yyfpv;			/* top of value stack */
int *yyfps;			/* top of state stack */

int yyfstate;			/* current state */
int yyftmp;			/* extra var (lasts between blocks) */

int yyfnerrs;			/* number of errors */
int yyferrflag;			/* error recovery flag */
int yyfchar;			/* current input token number */



#ifdef YYNMBCHARS
#define YYLEX()		yyfcvtok(yyflex())
/*
** yyfcvtok - return a token if i is a wchar_t value that exceeds 255.
**	If i<255, i itself is the token.  If i>255 but the neither 
**	of the 30th or 31st bit is on, i is already a token.
*/
#if defined(__STDC__) || defined(__cplusplus)
int yyfcvtok(int i)
#else
int yyfcvtok(i) int i;
#endif
{
	int first = 0;
	int last = YYNMBCHARS - 1;
	int mid;
	wchar_t j;

	if(i&0x60000000){/*Must convert to a token. */
		if( yyfmbchars[last].character < i ){
			return i;/*Giving up*/
		}
		while ((last>=first)&&(first>=0)) {/*Binary search loop*/
			mid = (first+last)/2;
			j = yyfmbchars[mid].character;
			if( j==i ){/*Found*/ 
				return yyfmbchars[mid].tvalue;
			}else if( j<i ){
				first = mid + 1;
			}else{
				last = mid -1;
			}
		}
		/*No entry in the table.*/
		return i;/* Giving up.*/
	}else{/* i is already a token. */
		return i;
	}
}
#else/*!YYNMBCHARS*/
#define YYLEX()		yyflex()
#endif/*!YYNMBCHARS*/

/*
** yyfparse - return 0 if worked, 1 if syntax error not recovered from
*/
#if defined(__STDC__) || defined(__cplusplus)
int yyfparse(void)
#else
int yyfparse()
#endif
{
	register YYSTYPE *yyfpvt;	/* top of value stack for $vars */

#if defined(__cplusplus) || defined(lint)
/*
	hacks to please C++ and lint - goto's inside switch should never be
	executed; yyfpvt is set to 0 to avoid "used before set" warning.
*/
	static int __yaccpar_lint_hack__ = 0;
	switch (__yaccpar_lint_hack__)
	{
		case 1: goto yyferrlab;
		case 2: goto yyfnewstate;
	}
	yyfpvt = 0;
#endif

	/*
	** Initialize externals - yyfparse may be called more than once
	*/
	yyfpv = &yyfv[-1];
	yyfps = &yyfs[-1];
	yyfstate = 0;
	yyftmp = 0;
	yyfnerrs = 0;
	yyferrflag = 0;
	yyfchar = -1;

#if YYMAXDEPTH <= 0
	if (yyfmaxdepth <= 0)
	{
		if ((yyfmaxdepth = YYEXPAND(0)) <= 0)
		{
			yyferror("yacc initialization error");
			YYABORT;
		}
	}
#endif

	{
		register YYSTYPE *yyf_pv;	/* top of value stack */
		register int *yyf_ps;		/* top of state stack */
		register int yyf_state;		/* current state */
		register int  yyf_n;		/* internal state number info */
	goto yyfstack;	/* moved from 6 lines above to here to please C++ */

		/*
		** get globals into registers.
		** branch to here only if YYBACKUP was called.
		*/
	yyfnewstate:
		yyf_pv = yyfpv;
		yyf_ps = yyfps;
		yyf_state = yyfstate;
		goto yyf_newstate;

		/*
		** get globals into registers.
		** either we just started, or we just finished a reduction
		*/
	yyfstack:
		yyf_pv = yyfpv;
		yyf_ps = yyfps;
		yyf_state = yyfstate;

		/*
		** top of for (;;) loop while no reductions done
		*/
	yyf_stack:
		/*
		** put a state and value onto the stacks
		*/
#if YYDEBUG
		/*
		** if debugging, look up token value in list of value vs.
		** name pairs.  0 and negative (-1) are special values.
		** Note: linear search is used since time is not a real
		** consideration while debugging.
		*/
		if ( yyfdebug )
		{
			register int yyf_i;

			printf( "State %d, token ", yyf_state );
			if ( yyfchar == 0 )
				printf( "end-of-file\n" );
			else if ( yyfchar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yyf_i = 0; yyftoks[yyf_i].t_val >= 0;
					yyf_i++ )
				{
					if ( yyftoks[yyf_i].t_val == yyfchar )
						break;
				}
				printf( "%s\n", yyftoks[yyf_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ++yyf_ps >= &yyfs[ yyfmaxdepth ] )	/* room on stack? */
		{
			/*
			** reallocate and recover.  Note that pointers
			** have to be reset, or bad things will happen
			*/
			int yyfps_index = (yyf_ps - yyfs);
			int yyfpv_index = (yyf_pv - yyfv);
			int yyfpvt_index = (yyfpvt - yyfv);
			int yyfnewmax;
#ifdef YYEXPAND
			yyfnewmax = YYEXPAND(yyfmaxdepth);
#else
			yyfnewmax = 2 * yyfmaxdepth;	/* double table size */
			if (yyfmaxdepth == YYMAXDEPTH)	/* first time growth */
			{
				char *newyyfs = (char *)YYNEW(int);
				char *newyyfv = (char *)YYNEW(YYSTYPE);
				if (newyyfs != 0 && newyyfv != 0)
				{
					yyfs = YYCOPY(newyyfs, yyfs, int);
					yyfv = YYCOPY(newyyfv, yyfv, YYSTYPE);
				}
				else
					yyfnewmax = 0;	/* failed */
			}
			else				/* not first time */
			{
				yyfs = YYENLARGE(yyfs, int);
				yyfv = YYENLARGE(yyfv, YYSTYPE);
				if (yyfs == 0 || yyfv == 0)
					yyfnewmax = 0;	/* failed */
			}
#endif
			if (yyfnewmax <= yyfmaxdepth)	/* tables not expanded */
			{
				yyferror( "yacc stack overflow" );
				YYABORT;
			}
			yyfmaxdepth = yyfnewmax;

			yyf_ps = yyfs + yyfps_index;
			yyf_pv = yyfv + yyfpv_index;
			yyfpvt = yyfv + yyfpvt_index;
		}
		*yyf_ps = yyf_state;
		*++yyf_pv = yyfval;

		/*
		** we have a new state - find out what to do
		*/
	yyf_newstate:
		if ( ( yyf_n = yyfpact[ yyf_state ] ) <= YYFLAG )
			goto yyfdefault;		/* simple state */
#if YYDEBUG
		/*
		** if debugging, need to mark whether new token grabbed
		*/
		yyftmp = yyfchar < 0;
#endif
		if ( ( yyfchar < 0 ) && ( ( yyfchar = YYLEX() ) < 0 ) )
			yyfchar = 0;		/* reached EOF */
#if YYDEBUG
		if ( yyfdebug && yyftmp )
		{
			register int yyf_i;

			printf( "Received token " );
			if ( yyfchar == 0 )
				printf( "end-of-file\n" );
			else if ( yyfchar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yyf_i = 0; yyftoks[yyf_i].t_val >= 0;
					yyf_i++ )
				{
					if ( yyftoks[yyf_i].t_val == yyfchar )
						break;
				}
				printf( "%s\n", yyftoks[yyf_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ( ( yyf_n += yyfchar ) < 0 ) || ( yyf_n >= YYLAST ) )
			goto yyfdefault;
		if ( yyfchk[ yyf_n = yyfact[ yyf_n ] ] == yyfchar )	/*valid shift*/
		{
			yyfchar = -1;
			yyfval = yyflval;
			yyf_state = yyf_n;
			if ( yyferrflag > 0 )
				yyferrflag--;
			goto yyf_stack;
		}

	yyfdefault:
		if ( ( yyf_n = yyfdef[ yyf_state ] ) == -2 )
		{
#if YYDEBUG
			yyftmp = yyfchar < 0;
#endif
			if ( ( yyfchar < 0 ) && ( ( yyfchar = YYLEX() ) < 0 ) )
				yyfchar = 0;		/* reached EOF */
#if YYDEBUG
			if ( yyfdebug && yyftmp )
			{
				register int yyf_i;

				printf( "Received token " );
				if ( yyfchar == 0 )
					printf( "end-of-file\n" );
				else if ( yyfchar < 0 )
					printf( "-none-\n" );
				else
				{
					for ( yyf_i = 0;
						yyftoks[yyf_i].t_val >= 0;
						yyf_i++ )
					{
						if ( yyftoks[yyf_i].t_val
							== yyfchar )
						{
							break;
						}
					}
					printf( "%s\n", yyftoks[yyf_i].t_name );
				}
			}
#endif /* YYDEBUG */
			/*
			** look through exception table
			*/
			{
				register int *yyfxi = yyfexca;

				while ( ( *yyfxi != -1 ) ||
					( yyfxi[1] != yyf_state ) )
				{
					yyfxi += 2;
				}
				while ( ( *(yyfxi += 2) >= 0 ) &&
					( *yyfxi != yyfchar ) )
					;
				if ( ( yyf_n = yyfxi[1] ) < 0 )
					YYACCEPT;
			}
		}

		/*
		** check for syntax error
		*/
		if ( yyf_n == 0 )	/* have an error */
		{
			/* no worry about speed here! */
			switch ( yyferrflag )
			{
			case 0:		/* new error */
				yyferror( "syntax error" );
				goto skip_init;
			yyferrlab:
				/*
				** get globals into registers.
				** we have a user generated syntax type error
				*/
				yyf_pv = yyfpv;
				yyf_ps = yyfps;
				yyf_state = yyfstate;
			skip_init:
				yyfnerrs++;
				/* FALLTHRU */
			case 1:
			case 2:		/* incompletely recovered error */
					/* try again... */
				yyferrflag = 3;
				/*
				** find state where "error" is a legal
				** shift action
				*/
				while ( yyf_ps >= yyfs )
				{
					yyf_n = yyfpact[ *yyf_ps ] + YYERRCODE;
					if ( yyf_n >= 0 && yyf_n < YYLAST &&
						yyfchk[yyfact[yyf_n]] == YYERRCODE)					{
						/*
						** simulate shift of "error"
						*/
						yyf_state = yyfact[ yyf_n ];
						goto yyf_stack;
					}
					/*
					** current state has no shift on
					** "error", pop stack
					*/
#if YYDEBUG
#	define _POP_ "Error recovery pops state %d, uncovers state %d\n"
					if ( yyfdebug )
						printf( _POP_, *yyf_ps,
							yyf_ps[-1] );
#	undef _POP_
#endif
					yyf_ps--;
					yyf_pv--;
				}
				/*
				** there is no state on stack with "error" as
				** a valid shift.  give up.
				*/
				YYABORT;
			case 3:		/* no shift yet; eat a token */
#if YYDEBUG
				/*
				** if debugging, look up token in list of
				** pairs.  0 and negative shouldn't occur,
				** but since timing doesn't matter when
				** debugging, it doesn't hurt to leave the
				** tests here.
				*/
				if ( yyfdebug )
				{
					register int yyf_i;

					printf( "Error recovery discards " );
					if ( yyfchar == 0 )
						printf( "token end-of-file\n" );
					else if ( yyfchar < 0 )
						printf( "token -none-\n" );
					else
					{
						for ( yyf_i = 0;
							yyftoks[yyf_i].t_val >= 0;
							yyf_i++ )
						{
							if ( yyftoks[yyf_i].t_val
								== yyfchar )
							{
								break;
							}
						}
						printf( "token %s\n",
							yyftoks[yyf_i].t_name );
					}
				}
#endif /* YYDEBUG */
				if ( yyfchar == 0 )	/* reached EOF. quit */
					YYABORT;
				yyfchar = -1;
				goto yyf_newstate;
			}
		}/* end if ( yyf_n == 0 ) */
		/*
		** reduction by production yyf_n
		** put stack tops, etc. so things right after switch
		*/
#if YYDEBUG
		/*
		** if debugging, print the string that is the user's
		** specification of the reduction which is just about
		** to be done.
		*/
		if ( yyfdebug )
			printf( "Reduce by (%d) \"%s\"\n",
				yyf_n, yyfreds[ yyf_n ] );
#endif
		yyftmp = yyf_n;			/* value to switch over */
		yyfpvt = yyf_pv;			/* $vars top of value stack */
		/*
		** Look in goto table for next state
		** Sorry about using yyf_state here as temporary
		** register variable, but why not, if it works...
		** If yyfr2[ yyf_n ] doesn't have the low order bit
		** set, then there is no action to be done for
		** this reduction.  So, no saving & unsaving of
		** registers done.  The only difference between the
		** code just after the if and the body of the if is
		** the goto yyf_stack in the body.  This way the test
		** can be made before the choice of what to do is needed.
		*/
		{
			/* length of production doubled with extra bit */
			register int yyf_len = yyfr2[ yyf_n ];

			if ( !( yyf_len & 01 ) )
			{
				yyf_len >>= 1;
				yyfval = ( yyf_pv -= yyf_len )[1];	/* $$ = $1 */
				yyf_state = yyfpgo[ yyf_n = yyfr1[ yyf_n ] ] +
					*( yyf_ps -= yyf_len ) + 1;
				if ( yyf_state >= YYLAST ||
					yyfchk[ yyf_state =
					yyfact[ yyf_state ] ] != -yyf_n )
				{
					yyf_state = yyfact[ yyfpgo[ yyf_n ] ];
				}
				goto yyf_stack;
			}
			yyf_len >>= 1;
			yyfval = ( yyf_pv -= yyf_len )[1];	/* $$ = $1 */
			yyf_state = yyfpgo[ yyf_n = yyfr1[ yyf_n ] ] +
				*( yyf_ps -= yyf_len ) + 1;
			if ( yyf_state >= YYLAST ||
				yyfchk[ yyf_state = yyfact[ yyf_state ] ] != -yyf_n )
			{
				yyf_state = yyfact[ yyfpgo[ yyf_n ] ];
			}
		}
					/* save until reenter driver code */
		yyfstate = yyf_state;
		yyfps = yyf_ps;
		yyfpv = yyf_pv;
	}
	/*
	** code supplied by user is placed in this switch
	*/
	switch( yyftmp )
	{
		
case 1:
# line 72 "filt_parser.y"
{InstallFilter(yyfpvt[-0].pf);} break;
case 2:
# line 76 "filt_parser.y"
{ yyfval.pf = yyfpvt[-0].pf; } break;
case 3:
# line 78 "filt_parser.y"
{ yyfval.pf = MakeUnaryNode(OP_NOT,yyfpvt[-0].pf); } break;
case 4:
# line 80 "filt_parser.y"
{ yyfval.pf = MakeBinaryNode(OP_AND,yyfpvt[-2].pf,yyfpvt[-0].pf); } break;
case 5:
# line 82 "filt_parser.y"
{ yyfval.pf = MakeBinaryNode(OP_OR,yyfpvt[-2].pf,yyfpvt[-0].pf); } break;
case 6:
# line 86 "filt_parser.y"
{ yyfval.pf = yyfpvt[-1].pf; } break;
case 7:
# line 88 "filt_parser.y"
{ yyfval.pf = yyfpvt[-0].pf; } break;
case 8:
# line 92 "filt_parser.y"
{yyfval.pf = MakeBinaryNode(yyfpvt[-1].op,yyfpvt[-2].pf,yyfpvt[-0].pf);} break;
case 9:
# line 96 "filt_parser.y"
{ yyfval.pf = MakeVarNode(yyfpvt[-0].string); } break;
case 10:
# line 98 "filt_parser.y"
{ yyfval.pf = MakeSignedConstNode(yyfpvt[-0].signed_long); } break;
case 11:
# line 100 "filt_parser.y"
{ yyfval.pf = MakeUnsignedConstNode(yyfpvt[-0].unsigned_long); } break;
case 12:
# line 102 "filt_parser.y"
{ yyfval.pf = MakeStringConstNode(yyfpvt[-0].string); } break;
case 13:
# line 104 "filt_parser.y"
{ yyfval.pf = MakeBoolConstNode(yyfpvt[-0].bool); } break;
case 14:
# line 108 "filt_parser.y"
{ yyfval.op = OP_GREATER;} break;
case 15:
# line 110 "filt_parser.y"
{ yyfval.op = OP_GREATER_EQ;} break;
case 16:
# line 112 "filt_parser.y"
{ yyfval.op = OP_LESS;} break;
case 17:
# line 114 "filt_parser.y"
{ yyfval.op = OP_LESS_EQ;} break;
case 18:
# line 116 "filt_parser.y"
{ yyfval.op = OP_EQUAL;} break;
case 19:
# line 118 "filt_parser.y"
{ yyfval.op = OP_NEQUAL;} break;
case 20:
# line 120 "filt_parser.y"
{ yyfval.op = OP_NOT;} break;
# line	532 "/usr/ccs/bin/yaccpar"
	}
	goto yyfstack;		/* reset registers in driver code */
}

