%{
/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999
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

#define yylval filtyylval

#include "filt_parser.h"

/* define our own input routine using filter_getc() */
#define YY_INPUT(buf,result,max_size) \
         { \
         int c = filter_getc(); \
         result = (c == EOF) ? YY_NULL : (buf[0] = c, 1); \
         }

%}

%%

[ \t]+		{ }  /* Just ignore white space */

"\n" 	        { return(EOS); } 
"+" 	        { return(PLUS); } 
"-" 	        { return(MINUS); } 
"*" 	        { return(TIMES); } 
"/" 	        { return(DIVIDE); } 
"%" 	        { return(MOD); } 
"(" 	        { return(LPAREN); } 
")" 	        { return(RPAREN); } 
"<" 	        { return(LESS); } 
"<=" 	        { return(LESS_EQ); } 
">" 	        { return(GREATER); } 
">=" 	        { return(GREATER_EQ); } 
"=" 	        { return(EQUAL); } 
"==" 	        { return(EQUAL); }   /* same as "=" */
"!=" 	        { return(NEQUAL); } 
"!" 	        { return(NOT); } 
[nN][oO][tT]	{ return(NOT); }   /* same as "!" */
[aA][nN][dD]	{ return(AND); } 
-[aA]		{ return(AND); }    /* same as "AND" */
"&&"		{ return(AND); }    /* same as "AND" */
[oO][rR]	{ return(OR); } 
-[oO]		{ return(OR); }     /* same as "OR" */
"||"		{ return(OR); }     /* same as "OR" */
"|"		{ return(BOR); }     /* bitwise OR */
"&"		{ return(BAND); }    /* bitwise AND */


[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ {
    /* an IPv4 addr */
    yylval.pipaddr = str2ipaddr(yytext);
    return(IPADDR);
}

[0-9a-fA-F]+:[:0-9a-fA-F]*:[0-9a-fA-F]+ {
    /* an IPv6 addr */
    yylval.pipaddr = str2ipaddr(yytext);
    return(IPADDR);
}

[0-9]+	{
    /* an unsigned integer */
    yylval.unsigned_long = atoi(yytext);
    return(UNSIGNED);
}

-[0-9]+	{
    /* a signed integer */
    yylval.signed_long = atoi(yytext);
    return(SIGNED);
}
"FALSE"	        { yylval.unsigned_long = 0; return(UNSIGNED); }
"TRUE"	        { yylval.unsigned_long = 1; return(UNSIGNED); }

\"[^\"]*\"	{
    /* a string */
    yylval.string = strdup(yytext+1);  /* make a copy of the string */
    yylval.string[strlen(yylval.string)-1] = '\00';
    return(STRING);
}

[a-zA-Z_][a-zA-Z_0-9\.]* {
    /* a variable (word) */
    yylval.string = strdup(yytext);  /* make a copy of the string */
    return(VARIABLE);
}


.		{
    /* if we haven't matched anything yet, then it's illegal */
    fprintf(stderr, "filter scanner: Bad character '%c' (%d decimal)\n",
	    *yytext, *yytext);
    exit(-1);
}


%%

int yywrap(void)
{
    if (0)
	unput(0);  /* never really called, but shuts up gcc */

    return(1);
}

