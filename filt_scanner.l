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

