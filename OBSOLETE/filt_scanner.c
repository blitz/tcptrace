#include <stdio.h>
# define U(x) x
# define NLSTATE yyfprevious=YYNEWLINE
# define BEGIN yyfbgin = yyfsvec + 1 +
# define INITIAL 0
# define YYLERR yyfsvec
# define YYSTATE (yyfestate-yyfsvec-1)
# define YYOPTIM 1
# define YYLMAX BUFSIZ
#ifndef __cplusplus
# define output(c) (void)putc(c,yyfout)
#else
# define lex_output(c) (void)putc(c,yyfout)
#endif

#if defined(__cplusplus) || defined(__STDC__)

#if defined(__cplusplus) && defined(__EXTERN_C__)
extern "C" {
#endif
	int yyfback(int *, int);
	int yyfinput(void);
	int yyflook(void);
	void yyfoutput(int);
	int yyfracc(int);
	int yyfreject(void);
	void yyfunput(int);
	int yyflex(void);
#ifdef YYLEX_E
	void yyfwoutput(wchar_t);
	wchar_t yyfwinput(void);
#endif
#ifndef yyfless
	int yyfless(int);
#endif
#ifndef yyfwrap
	int yyfwrap(void);
#endif
#ifdef LEXDEBUG
	void allprint(char);
	void sprint(char *);
#endif
#if defined(__cplusplus) && defined(__EXTERN_C__)
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
	void exit(int);
#ifdef __cplusplus
}
#endif

#endif
# define unput(c) {yyftchar= (c);if(yyftchar=='\n')yyflineno--;*yyfsptr++=yyftchar;}
# define yyfmore() (yyfmorfg=1)
#ifndef __cplusplus
# define input() (((yyftchar=yyfsptr>yyfsbuf?U(*--yyfsptr):getc(yyfin))==10?(yyflineno++,yyftchar):yyftchar)==EOF?0:yyftchar)
#else
# define lex_input() (((yyftchar=yyfsptr>yyfsbuf?U(*--yyfsptr):getc(yyfin))==10?(yyflineno++,yyftchar):yyftchar)==EOF?0:yyftchar)
#endif
#define ECHO fprintf(yyfout, "%s",yyftext)
# define REJECT { nstr = yyfreject(); goto yyffussy;}
int yyfleng;
char yyftext[YYLMAX];
int yyfmorfg;
extern char *yyfsptr, yyfsbuf[];
int yyftchar;
FILE *yyfin = {stdin}, *yyfout = {stdout};
extern int yyflineno;
struct yyfsvf { 
	struct yyfwork *yyfstoff;
	struct yyfsvf *yyfother;
	int *yyfstops;};
struct yyfsvf *yyfestate;
extern struct yyfsvf yyfsvec[], *yyfbgin;

# line 3 "filt_scanner.l"
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


#include <string.h>
#include "tcptrace.h"
#include "filter.h"
#include "y.tab.h"

extern YYSTYPE yyflval;


# line 39 "filt_scanner.l"
/* define our own input routine using filter_getc() */
#undef input
#define input() (((yyftchar=yyfsptr>yyfsbuf?U(*--yyfsptr):filter_getc(yyfin))==10?(yyflineno++,yyftchar):yyftchar)==EOF?0:yyftchar)
# define YYNEWLINE 10
yyflex(){
int nstr; extern int yyfprevious;
#ifdef __cplusplus
/* to avoid CC and lint complaining yyffussy not being used ...*/
static int __lex_hack = 0;
if (__lex_hack) goto yyffussy;
#endif
while((nstr = yyflook()) >= 0)
yyffussy: switch(nstr){
case 0:
if(yyfwrap()) return(0); break;
case 1:

# line 45 "filt_scanner.l"
	{ }
break;
case 2:

# line 47 "filt_scanner.l"
	        { return(LPAREN); }
break;
case 3:

# line 48 "filt_scanner.l"
	        { return(RPAREN); }
break;
case 4:

# line 49 "filt_scanner.l"
	        { return(LESS); }
break;
case 5:

# line 50 "filt_scanner.l"
	        { return(LESS_EQ); }
break;
case 6:

# line 51 "filt_scanner.l"
	        { return(GREATER); }
break;
case 7:

# line 52 "filt_scanner.l"
	        { return(GREATER_EQ); }
break;
case 8:

# line 53 "filt_scanner.l"
	        { return(EQUAL); }
break;
case 9:

# line 54 "filt_scanner.l"
	        { return(EQUAL); }
break;
case 10:

# line 55 "filt_scanner.l"
	        { return(NEQUAL); }
break;
case 11:

# line 56 "filt_scanner.l"
	        { return(NOT); }
break;
case 12:

# line 57 "filt_scanner.l"
{ return(NOT); }
break;
case 13:

# line 58 "filt_scanner.l"
{ return(AND); }
break;
case 14:

# line 59 "filt_scanner.l"
	{ return(AND); }
break;
case 15:

# line 60 "filt_scanner.l"
{ return(OR); }
break;
case 16:

# line 61 "filt_scanner.l"
	{ return(OR); }
break;
case 17:

# line 64 "filt_scanner.l"
{
    /* an unsigned integer */
    yyflval.unsigned_long = atoi(yyftext);
    return(UNSIGNED);
}
break;
case 18:

# line 70 "filt_scanner.l"
{
    /* a signed integer */
    yyflval.signed_long = atoi(yyftext);
    return(SIGNED);
}
break;
case 19:

# line 76 "filt_scanner.l"
        { yyflval.unsigned_long = 0; return(UNSIGNED); }
break;
case 20:

# line 77 "filt_scanner.l"
        { yyflval.unsigned_long = 1; return(UNSIGNED); }
break;
case 21:

# line 79 "filt_scanner.l"
{
    /* a string */
    yyflval.string = strdup(yyftext+1);  /* make a copy of the string */
    yyflval.string[strlen(yyflval.string)-1] = '\00';
    return(STRING);
}
break;
case 22:

# line 86 "filt_scanner.l"
{
    /* a variable (word) */
    yyflval.string = strdup(yyftext);  /* make a copy of the string */
    return(VARIABLE);
}
break;
case 23:

# line 93 "filt_scanner.l"
	{
    /* if we haven't matched anything yet, then it's illegal */
    fprintf(stderr, "filter scanner: Bad character '%c'\n", *yyftext);
    exit(-1);
}
break;
case -1:
break;
default:
(void)fprintf(yyfout,"bad switch yyflook %d",nstr);
} return(0); }
/* end of yyflex */

int yyfwrap(void)
{
    return(1);
}

int yyfvstop[] = {
0,

23,
0,

1,
23,
0,

11,
23,
0,

23,
0,

2,
23,
0,

3,
23,
0,

23,
0,

17,
23,
0,

4,
23,
0,

8,
23,
0,

6,
23,
0,

22,
23,
0,

22,
23,
0,

22,
23,
0,

22,
23,
0,

22,
23,
0,

22,
23,
0,

1,
0,

10,
0,

21,
0,

18,
0,

14,
0,

16,
0,

17,
0,

5,
0,

9,
0,

7,
0,

22,
0,

22,
0,

22,
0,

22,
0,

15,
22,
0,

22,
0,

13,
22,
0,

22,
0,

12,
22,
0,

22,
0,

22,
0,

20,
22,
0,

19,
22,
0,
0};
# define YYTYPE unsigned char
struct yyfwork { YYTYPE verify, advance; } yyfcrank[] = {
0,0,	0,0,	1,3,	0,0,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	1,4,	1,0,	
0,0,	4,20,	0,0,	0,0,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	2,0,	6,22,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	0,0,	6,22,	
6,22,	0,0,	1,5,	1,6,	
4,20,	0,0,	0,0,	0,0,	
0,0,	1,7,	1,8,	0,0,	
0,0,	2,5,	1,9,	0,0,	
0,0,	1,10,	0,0,	0,0,	
2,7,	2,8,	0,0,	0,0,	
6,23,	2,9,	0,0,	0,0,	
0,0,	1,11,	1,12,	1,13,	
5,21,	11,28,	1,14,	1,15,	
12,29,	1,15,	6,22,	1,16,	
2,11,	2,12,	2,13,	13,30,	
16,33,	0,0,	0,0,	1,17,	
1,18,	0,0,	2,16,	1,15,	
0,0,	1,19,	15,31,	6,22,	
6,22,	16,31,	6,22,	18,31,	
0,0,	17,31,	17,34,	18,35,	
0,0,	31,31,	19,31,	35,31,	
6,22,	6,22,	19,36,	33,38,	
6,22,	33,31,	6,22,	9,24,	
9,24,	9,24,	9,24,	9,24,	
9,24,	9,24,	9,24,	9,24,	
9,24,	1,15,	15,31,	37,31,	
39,31,	16,31,	42,31,	18,31,	
9,25,	17,31,	17,34,	18,35,	
2,15,	31,31,	19,31,	35,31,	
0,0,	0,0,	0,0,	43,31,	
0,0,	33,31,	9,26,	10,27,	
10,27,	10,27,	10,27,	10,27,	
10,27,	10,27,	10,27,	10,27,	
10,27,	0,0,	0,0,	37,31,	
39,31,	0,0,	42,31,	0,0,	
9,25,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	43,31,	
38,31,	0,0,	9,26,	0,0,	
0,0,	38,41,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,32,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
38,31,	0,0,	0,0,	0,0,	
14,31,	0,0,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,32,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
14,31,	14,31,	14,31,	14,31,	
24,24,	24,24,	24,24,	24,24,	
24,24,	24,24,	24,24,	24,24,	
24,24,	24,24,	32,37,	34,31,	
36,31,	40,42,	41,43,	0,0,	
0,0,	34,39,	0,0,	36,40,	
32,31,	0,0,	40,31,	41,31,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	0,0,	0,0,	
0,0,	0,0,	32,37,	34,31,	
36,31,	0,0,	0,0,	0,0,	
0,0,	34,39,	0,0,	0,0,	
32,31,	0,0,	40,31,	41,31,	
0,0};
struct yyfsvf yyfsvec[] = {
0,	0,	0,
yyfcrank+-1,	0,		0,	
yyfcrank+-12,	yyfsvec+1,	0,	
yyfcrank+0,	0,		yyfvstop+1,
yyfcrank+4,	0,		yyfvstop+3,
yyfcrank+3,	0,		yyfvstop+6,
yyfcrank+-22,	0,		yyfvstop+9,
yyfcrank+0,	0,		yyfvstop+11,
yyfcrank+0,	0,		yyfvstop+14,
yyfcrank+59,	0,		yyfvstop+17,
yyfcrank+91,	0,		yyfvstop+19,
yyfcrank+4,	0,		yyfvstop+22,
yyfcrank+7,	0,		yyfvstop+25,
yyfcrank+14,	0,		yyfvstop+28,
yyfcrank+109,	0,		yyfvstop+31,
yyfcrank+8,	yyfsvec+14,	yyfvstop+34,
yyfcrank+11,	yyfsvec+14,	yyfvstop+37,
yyfcrank+15,	yyfsvec+14,	yyfvstop+40,
yyfcrank+13,	yyfsvec+14,	yyfvstop+43,
yyfcrank+20,	yyfsvec+14,	yyfvstop+46,
yyfcrank+0,	yyfsvec+4,	yyfvstop+49,
yyfcrank+0,	0,		yyfvstop+51,
yyfcrank+0,	yyfsvec+6,	0,	
yyfcrank+0,	0,		yyfvstop+53,
yyfcrank+184,	0,		yyfvstop+55,
yyfcrank+0,	0,		yyfvstop+57,
yyfcrank+0,	0,		yyfvstop+59,
yyfcrank+0,	yyfsvec+10,	yyfvstop+61,
yyfcrank+0,	0,		yyfvstop+63,
yyfcrank+0,	0,		yyfvstop+65,
yyfcrank+0,	0,		yyfvstop+67,
yyfcrank+19,	yyfsvec+14,	yyfvstop+69,
yyfcrank+174,	yyfsvec+14,	yyfvstop+71,
yyfcrank+27,	yyfsvec+14,	yyfvstop+73,
yyfcrank+165,	yyfsvec+14,	yyfvstop+75,
yyfcrank+21,	yyfsvec+14,	yyfvstop+77,
yyfcrank+166,	yyfsvec+14,	yyfvstop+80,
yyfcrank+41,	yyfsvec+14,	yyfvstop+82,
yyfcrank+90,	yyfsvec+14,	yyfvstop+85,
yyfcrank+42,	yyfsvec+14,	yyfvstop+87,
yyfcrank+176,	yyfsvec+14,	yyfvstop+90,
yyfcrank+177,	yyfsvec+14,	yyfvstop+92,
yyfcrank+44,	yyfsvec+14,	yyfvstop+94,
yyfcrank+57,	yyfsvec+14,	yyfvstop+97,
0,	0,	0};
struct yyfwork *yyftop = yyfcrank+287;
struct yyfsvf *yyfbgin = yyfsvec+1;
char yyfmatch[] = {
  0,   1,   1,   1,   1,   1,   1,   1, 
  1,   9,  10,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  9,   1,  34,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
 48,  48,  48,  48,  48,  48,  48,  48, 
 48,  48,   1,   1,   1,   1,   1,   1, 
  1,  65,  66,  66,  68,  66,  66,  66, 
 66,  66,  66,  66,  66,  66,  78,  79, 
 66,  66,  82,  66,  84,  66,  66,  66, 
 66,  66,  66,   1,   1,   1,   1,  66, 
  1,  65,  66,  66,  68,  66,  66,  66, 
 66,  66,  66,  66,  66,  66,  78,  79, 
 66,  66,  82,  66,  84,  66,  66,  66, 
 66,  66,  66,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
  1,   1,   1,   1,   1,   1,   1,   1, 
0};
char yyfextra[] = {
0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0};
/*	Copyright (c) 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF AT&T	*/
/*	The copyright notice above does not evidence any   	*/
/*	actual or intended publication of such source code.	*/

#pragma ident	"@(#)ncform	6.8	95/02/11 SMI"

int yyflineno =1;
# define YYU(x) x
# define NLSTATE yyfprevious=YYNEWLINE
struct yyfsvf *yyflstate [YYLMAX], **yyflsp, **yyfolsp;
char yyfsbuf[YYLMAX];
char *yyfsptr = yyfsbuf;
int *yyffnd;
extern struct yyfsvf *yyfestate;
int yyfprevious = YYNEWLINE;
#if defined(__cplusplus) || defined(__STDC__)
int yyflook(void)
#else
yyflook()
#endif
{
	register struct yyfsvf *yyfstate, **lsp;
	register struct yyfwork *yyft;
	struct yyfsvf *yyfz;
	int yyfch, yyffirst;
	struct yyfwork *yyfr;
# ifdef LEXDEBUG
	int debug;
# endif
	char *yyflastch;
	/* start off machines */
# ifdef LEXDEBUG
	debug = 0;
# endif
	yyffirst=1;
	if (!yyfmorfg)
		yyflastch = yyftext;
	else {
		yyfmorfg=0;
		yyflastch = yyftext+yyfleng;
		}
	for(;;){
		lsp = yyflstate;
		yyfestate = yyfstate = yyfbgin;
		if (yyfprevious==YYNEWLINE) yyfstate++;
		for (;;){
# ifdef LEXDEBUG
			if(debug)fprintf(yyfout,"state %d\n",yyfstate-yyfsvec-1);
# endif
			yyft = yyfstate->yyfstoff;
			if(yyft == yyfcrank && !yyffirst){  /* may not be any transitions */
				yyfz = yyfstate->yyfother;
				if(yyfz == 0)break;
				if(yyfz->yyfstoff == yyfcrank)break;
				}
#ifndef __cplusplus
			*yyflastch++ = yyfch = input();
#else
			*yyflastch++ = yyfch = lex_input();
#endif
			if(yyflastch > &yyftext[YYLMAX]) {
				fprintf(yyfout,"Input string too long, limit %d\n",YYLMAX);
				exit(1);
			}
			yyffirst=0;
		tryagain:
# ifdef LEXDEBUG
			if(debug){
				fprintf(yyfout,"char ");
				allprint(yyfch);
				putchar('\n');
				}
# endif
			yyfr = yyft;
			if ( (int)yyft > (int)yyfcrank){
				yyft = yyfr + yyfch;
				if (yyft <= yyftop && yyft->verify+yyfsvec == yyfstate){
					if(yyft->advance+yyfsvec == YYLERR)	/* error transitions */
						{unput(*--yyflastch);break;}
					*lsp++ = yyfstate = yyft->advance+yyfsvec;
					if(lsp > &yyflstate[YYLMAX]) {
						fprintf(yyfout,"Input string too long, limit %d\n",YYLMAX);
						exit(1);
					}
					goto contin;
					}
				}
# ifdef YYOPTIM
			else if((int)yyft < (int)yyfcrank) {		/* r < yyfcrank */
				yyft = yyfr = yyfcrank+(yyfcrank-yyft);
# ifdef LEXDEBUG
				if(debug)fprintf(yyfout,"compressed state\n");
# endif
				yyft = yyft + yyfch;
				if(yyft <= yyftop && yyft->verify+yyfsvec == yyfstate){
					if(yyft->advance+yyfsvec == YYLERR)	/* error transitions */
						{unput(*--yyflastch);break;}
					*lsp++ = yyfstate = yyft->advance+yyfsvec;
					if(lsp > &yyflstate[YYLMAX]) {
						fprintf(yyfout,"Input string too long, limit %d\n",YYLMAX);
						exit(1);
					}
					goto contin;
					}
				yyft = yyfr + YYU(yyfmatch[yyfch]);
# ifdef LEXDEBUG
				if(debug){
					fprintf(yyfout,"try fall back character ");
					allprint(YYU(yyfmatch[yyfch]));
					putchar('\n');
					}
# endif
				if(yyft <= yyftop && yyft->verify+yyfsvec == yyfstate){
					if(yyft->advance+yyfsvec == YYLERR)	/* error transition */
						{unput(*--yyflastch);break;}
					*lsp++ = yyfstate = yyft->advance+yyfsvec;
					if(lsp > &yyflstate[YYLMAX]) {
						fprintf(yyfout,"Input string too long, limit %d\n",YYLMAX);
						exit(1);
					}
					goto contin;
					}
				}
			if ((yyfstate = yyfstate->yyfother) && (yyft= yyfstate->yyfstoff) != yyfcrank){
# ifdef LEXDEBUG
				if(debug)fprintf(yyfout,"fall back to state %d\n",yyfstate-yyfsvec-1);
# endif
				goto tryagain;
				}
# endif
			else
				{unput(*--yyflastch);break;}
		contin:
# ifdef LEXDEBUG
			if(debug){
				fprintf(yyfout,"state %d char ",yyfstate-yyfsvec-1);
				allprint(yyfch);
				putchar('\n');
				}
# endif
			;
			}
# ifdef LEXDEBUG
		if(debug){
			fprintf(yyfout,"stopped at %d with ",*(lsp-1)-yyfsvec-1);
			allprint(yyfch);
			putchar('\n');
			}
# endif
		while (lsp-- > yyflstate){
			*yyflastch-- = 0;
			if (*lsp != 0 && (yyffnd= (*lsp)->yyfstops) && *yyffnd > 0){
				yyfolsp = lsp;
				if(yyfextra[*yyffnd]){		/* must backup */
					while(yyfback((*lsp)->yyfstops,-*yyffnd) != 1 && lsp > yyflstate){
						lsp--;
						unput(*yyflastch--);
						}
					}
				yyfprevious = YYU(*yyflastch);
				yyflsp = lsp;
				yyfleng = yyflastch-yyftext+1;
				yyftext[yyfleng] = 0;
# ifdef LEXDEBUG
				if(debug){
					fprintf(yyfout,"\nmatch ");
					sprint(yyftext);
					fprintf(yyfout," action %d\n",*yyffnd);
					}
# endif
				return(*yyffnd++);
				}
			unput(*yyflastch);
			}
		if (yyftext[0] == 0  /* && feof(yyfin) */)
			{
			yyfsptr=yyfsbuf;
			return(0);
			}
#ifndef __cplusplus
		yyfprevious = yyftext[0] = input();
		if (yyfprevious>0)
			output(yyfprevious);
#else
		yyfprevious = yyftext[0] = lex_input();
		if (yyfprevious>0)
			lex_output(yyfprevious);
#endif
		yyflastch=yyftext;
# ifdef LEXDEBUG
		if(debug)putchar('\n');
# endif
		}
	}
#if defined(__cplusplus) || defined(__STDC__)
int yyfback(int *p, int m)
#else
yyfback(p, m)
	int *p;
#endif
{
	if (p==0) return(0);
	while (*p) {
		if (*p++ == m)
			return(1);
	}
	return(0);
}
	/* the following are only used in the lex library */
#if defined(__cplusplus) || defined(__STDC__)
int yyfinput(void)
#else
yyfinput()
#endif
{
#ifndef __cplusplus
	return(input());
#else
	return(lex_input());
#endif
	}
#if defined(__cplusplus) || defined(__STDC__)
void yyfoutput(int c)
#else
yyfoutput(c)
  int c; 
#endif
{
#ifndef __cplusplus
	output(c);
#else
	lex_output(c);
#endif
	}
#if defined(__cplusplus) || defined(__STDC__)
void yyfunput(int c)
#else
yyfunput(c)
   int c; 
#endif
{
	unput(c);
	}
