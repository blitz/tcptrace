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
#include "y.tab.h"
#include "filter.h"
#include "filter_vars.h"


/* local globals */
static char *exprstr = NULL;
static struct filter_node *filter_root = NULL;

char*
Op2Str(
    int op)
{
    switch (op) {
      case AND:		return("AND");
      case OR:		return("OR");
      case GREATER:	return(">");
      case GREATER_EQ:	return(">=");
      case LESS:	return("<");
      case LESS_EQ:	return("<=");
      case EQUAL:	return("==");
      case NEQUAL:	return("!=");
      default:		return("??");
    }
}




char*
Vartype2Str(
    enum vartype vartype)
{
    switch (vartype) {
      case V_FLOAT: return("V_FLOAT");
      case V_UCHAR: return("V_UCHAR");
      case V_UINT: return("V_UINT");
      case V_ULONG: return("V_ULONG");
      case V_USHORT: return("V_USHORT");
      case V_BOOL: return("V_BOOL");
      case V_CHAR: return("V_CHAR");
      case V_INT: return("V_INT");
      case V_LLONG: return("V_LLONG");
      case V_LONG: return("V_LONG");
      case V_SHORT: return("V_SHORT");
      case V_STRING: return("V_STRING");
      case V_ULLONG: return("V_ULLONG");
    }

    fprintf(stderr,"Vartype2Str: Internal error, unknown type %d\n",
	    vartype);
    exit(-1);
}


struct filter_node *
MakeFilterNode(int op)
{
    struct filter_node *pn;

    pn = MallocZ(sizeof(struct filter_node));
    pn->op = op;

    return(pn);
}


struct var_node *
MakeVarNode(enum vartype vartype,
	    Bool fconstant)
{
    struct var_node *pn;

    pn = MallocZ(sizeof(struct var_node));
    pn->vartype = vartype;
    pn->isconstant = fconstant;

    return(pn);
}


char *
PrintLeaf(
    struct var_node *pv)
{
    char buf[100];
    
    /* for variables */
    if (!pv->isconstant) {
	sprintf(buf,"Var(%s,\"%s\")",
		Vartype2Str(pv->vartype),
		pv->unIsConst.vardet.name);
    } else {
	/* for constants */
	switch (pv->vartype) {
	  case V_ULONG:	sprintf(buf,"ULONG(%lu)",pv->unIsConst.unType.u_longint); break;
	  case V_LONG:	sprintf(buf,"LONG(%ld)" ,pv->unIsConst.unType.longint); break;
	  case V_FLOAT:	sprintf(buf,"FLOAT(%f)" ,pv->unIsConst.unType.floating); break;
	  case V_STRING:sprintf(buf,"STRING(%s)" ,pv->unIsConst.unType.string); break;
	  case V_BOOL:	sprintf(buf,"BOOL(%d)" ,pv->unIsConst.unType.bool); break;
	  default: return("<unknown>");
	}
    }

    /* small memory leak, but it's just done once */
    return(strdup(buf));
}


void
PrintFilter(
    struct filter_node *pn)
{
    if (!pn)
	return;

    if ((pn->op == AND) || (pn->op == OR)) {
	PrintFilter(pn->un.bool.left);
	if (pn->op == AND)
	    printf(" AND ");
	else
	    printf(" OR ");
	PrintFilter(pn->un.bool.right);
	return;
    } else if (pn->op == NOT) {
	printf("NOT(");
	PrintFilter(pn->un.bool.left);
	printf(")");
	return;
    }

    printf("(%s %s %s)",
	   PrintLeaf(pn->un.leaf.pvarl),
	   Op2Str(pn->op),
	   PrintLeaf(pn->un.leaf.pvarr));
}






void
ParseFilter(
    char *expr)
{
    exprstr = strdup(expr);

    if (debug)
	printf("Parsefilter('%s') called\n", expr);

    if (debug > 1)
	yyfdebug = 1;

    if (yyfparse() == 0) {
	/* it worked */
	printf("Current filter:  ");
	PrintFilter(filter_root);
	printf("\n");
    } else {
	/* parsing failed */
	fprintf(stderr,"Filter parsing failed\n");
	exit(-1);
    }
}


struct var_node *
LookupVar(
    char *varname,
    Bool fclient)
{
    int i;
    struct var_node *pv;
    void *ptr;

    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pf = &filters[i];
	if (strcasecmp(varname,pf->varname) == 0) {
	    /* we found it */
	    pv = MakeVarNode(pf->vartype,FALSE);
	    pv->unIsConst.vardet.name = strdup(varname);
	    if (fclient)
		ptr = (void *)pf->cl_addr;
	    else
		ptr = (void *)pf->sv_addr;
	    pv->unIsConst.vardet.offset = ptr - (void *)&ptp_dummy;

	    return(pv);
	}
    }

    /* not found */
    fprintf(stderr,"Variable \"%s\" not found\n", varname);
    exit(-1);
}

static u_llong
Ptr2Signed(
    enum vartype vartype,
    void *ptr)
{
    u_llong val;

    switch (vartype) {
      case V_LLONG:	val = *((llong *) ptr); break;
      case V_LONG:	val = *((long *) ptr); break;
      case V_INT:	val = *((int *) ptr); break;
      case V_SHORT:	val = *((short *) ptr); break;
      case V_CHAR:	val = *((char *) ptr); break;
      default: {
	  fprintf(stderr,
		  "Ptr2Signed: can't convert type %s to signed\n",
		  Vartype2Str(vartype));
	  exit(-1);
      }
    }
    return(val);
}

static u_llong
Ptr2Unsigned(
    enum vartype vartype,
    void *ptr)
{
    u_llong val;

    switch (vartype) {
      case V_ULLONG:	val = *((u_llong *) ptr); break;
      case V_ULONG:	val = *((u_long *) ptr); break;
      case V_UINT:	val = *((u_int *) ptr); break;
      case V_USHORT:	val = *((u_short *) ptr); break;
      case V_UCHAR:	val = *((u_char *) ptr); break;
      case V_BOOL:	val = *((Bool *) ptr)==TRUE; break;
      default: {
	  fprintf(stderr,
		  "Ptr2Unsigned: can't convert type %s to unsigned\n",
		  Vartype2Str(vartype));
	  exit(-1);
      }

    }
    return(val);
}



static char *
Var2String(
    tcp_pair *ptp,
    struct var_node *pv)
{
    void *ptr;
    char *str;

    ptr = (char *)ptp + pv->unIsConst.vardet.offset;
    str = *((char **)ptr);

    if (str == NULL)
	str = "<NULL>";

    if (debug)
	printf("Var2String returns 0x%08x (%s)\n",
	       (u_int) str, str);

    return(str);
}


static u_long
Var2Signed(
    tcp_pair *ptp,
    struct var_node *pv)
{
    void *ptr;

    ptr = (char *)ptp + pv->unIsConst.vardet.offset;

    switch (pv->vartype) {
      case V_ULLONG: return(Ptr2Signed(V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Signed(V_ULONG,ptr));
      case V_UINT:   return(Ptr2Signed(V_UINT,ptr));
      case V_USHORT: return(Ptr2Signed(V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Signed(V_UCHAR,ptr));
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %s to signed\n",
		  Vartype2Str(pv->vartype));
	  exit(-1);
      }
    }
}


static u_long
Var2Unsigned(
    tcp_pair *ptp,
    struct var_node *pv)
{
    void *ptr;

    ptr = (char *)ptp + pv->unIsConst.vardet.offset;

    switch (pv->vartype) {
      case V_ULLONG: return(Ptr2Unsigned(V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Unsigned(V_ULONG,ptr));
      case V_UINT:   return(Ptr2Unsigned(V_UINT,ptr));
      case V_USHORT: return(Ptr2Unsigned(V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Unsigned(V_UCHAR,ptr));
      case V_BOOL:   return(Ptr2Unsigned(V_BOOL,ptr));
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %s to unsigned\n",
		  Vartype2Str(pv->vartype));
	  exit(-1);
      }
    }
}


static u_llong
Const2Unsigned(
    struct var_node *pv)
{
    switch (pv->vartype) {
      case V_ULONG:	return((u_llong) pv->unIsConst.unType.u_longint);
      case V_LONG:	return((u_llong) pv->unIsConst.unType.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d to unsigned\n",
		  pv->vartype);
	  exit(-1);
      }
    }
}


static llong
Const2Signed(
    struct var_node *pv)
{
    switch (pv->vartype) {
      case V_ULONG:	return((llong) pv->unIsConst.unType.u_longint);
      case V_LONG:	return((llong) pv->unIsConst.unType.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d to long\n",
		  pv->vartype);
	  exit(-1);
      }
    }
}


/* evaluate a leaf-node UNSigned NUMBER */
static Bool
EvalUnsigned(
    tcp_pair *ptp,
    struct filter_node *pn)
{
    u_llong varl;
    u_llong varr;
    Bool ret;

    /* grab left hand side */
    if (pn->un.leaf.pvarl->isconstant) {
	varl = Const2Unsigned(pn->un.leaf.pvarl);
    } else {
	varl = Var2Unsigned(ptp,pn->un.leaf.pvarl);
    }
    

    /* grab right hand side */
    if (pn->un.leaf.pvarr->isconstant) {
	varr = Const2Unsigned(pn->un.leaf.pvarr);
	if (pn->un.leaf.pvarl->vartype == V_BOOL)
	    varr = (varr==TRUE); /* convert unsigned to boolean */
    } else {
	varr = Var2Unsigned(ptp,pn->un.leaf.pvarr);
    }

    switch (pn->op) {
      case GREATER:	ret = (varl >  varr); break;
      case GREATER_EQ:	ret = (varl >= varr); break;
      case LESS:	ret = (varl <  varr); break;
      case LESS_EQ:	ret = (varl <= varr); break;
      case EQUAL:	ret = (varl == varr); break;
      case NEQUAL:	ret = (varl != varr); break;
      default: {
	  fprintf(stderr,"EvalUnsigned: internal error\n");
	  exit(-1);
      }
    }

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalUnsigned %llu %s %llu returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalUnsigned %lu %s %lu returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pn->op), varr,
	       ret?"TRUE":"FALSE");

    return(ret);
}


/* evaluate a leaf-node string */
static Bool
EvalString(
    tcp_pair *ptp,
    struct filter_node *pn)
{
    char *varl;
    char *varr;
    Bool ret;
    int cmp;

    /* grab left hand side */
    if (pn->un.leaf.pvarl->isconstant)
	varl = pn->un.leaf.pvarl->unIsConst.unType.string;
    else
	varl = Var2String(ptp,pn->un.leaf.pvarl);
    

    /* grab right hand side */
    if (pn->un.leaf.pvarr->isconstant)
	varr = pn->un.leaf.pvarr->unIsConst.unType.string;
    else
	varr = Var2String(ptp,pn->un.leaf.pvarr);

    cmp = strcmp(varl,varr);

    switch (pn->op) {
      case GREATER:	ret = (cmp >  0); break;
      case GREATER_EQ:	ret = (cmp >= 0); break;
      case LESS:	ret = (cmp <  0); break;
      case LESS_EQ:	ret = (cmp <= 0); break;
      case EQUAL:	ret = (cmp == 0); break;
      case NEQUAL:	ret = (cmp != 0); break;
      default: {
	  fprintf(stderr,"EvalString: internal error\n");
	  exit(-1);
      }
    }

    if (debug)
	printf("EvalString '%s' %s '%s' returns %s\n",
	       varl, Op2Str(pn->op), varr, 
	       ret?"TRUE":"FALSE");

    return(ret);
}


/* evaluate a leaf-node Signed NUMBER */
static Bool
EvalSigned(
    tcp_pair *ptp,
    struct filter_node *pn)
{
    llong varl;
    llong varr;
    Bool ret;

    /* grab left hand side */
    if (pn->un.leaf.pvarl->isconstant)
	varl = Const2Signed(pn->un.leaf.pvarl);
    else
	varl = Var2Signed(ptp,pn->un.leaf.pvarl);
    

    /* grab right hand side */
    if (pn->un.leaf.pvarr->isconstant)
	varr = Const2Signed(pn->un.leaf.pvarr);
    else
	varr = Var2Signed(ptp,pn->un.leaf.pvarr);

    switch (pn->op) {
      case GREATER:	ret = (varl >  varr); break;
      case GREATER_EQ:	ret = (varl >= varr); break;
      case LESS:	ret = (varl <  varr); break;
      case LESS_EQ:	ret = (varl <= varr); break;
      case EQUAL:	ret = (varl == varr); break;
      case NEQUAL:	ret = (varl != varr); break;
      default: {
	  fprintf(stderr,"EvalSigned: internal error\n");
	  exit(-1);
      }
    }

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalSigned %lld %s %lld returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalSigned %ld %s %ld returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pn->op), varr, 
	       ret?"TRUE":"FALSE");

    return(ret);
}



/* eval a leaf node */
static Bool
EvalLeaf(
    tcp_pair *ptp,
    struct filter_node *pn)
{
    Bool ret;

    switch(pn->un.leaf.pvarl->vartype) {
      case V_ULLONG:
      case V_ULONG:
      case V_UINT:
      case V_USHORT:
      case V_UCHAR:
      case V_BOOL:
	ret = EvalUnsigned(ptp,pn); break;

      case V_LLONG:
      case V_LONG:
      case V_SHORT:
      case V_INT:
      case V_CHAR:
	ret = EvalSigned(ptp,pn); break;

      case V_STRING:
	ret = EvalString(ptp,pn); break;

      default: {
	    fprintf(stderr,"EvalLeaf: type %s not implemented\n",
		    Vartype2Str(pn->un.leaf.pvarl->vartype));
	    exit(-1);
	}
    }

    return(ret);
}


Bool
EvalFilter(
    tcp_pair *ptp,
    struct filter_node *pn)
{
    if (!pn)
	return(TRUE);

    if (pn->op == AND)
	return(EvalFilter(ptp,pn->un.bool.left) && EvalFilter(ptp,pn->un.bool.right));
    
    if (pn->op == OR)
	return(EvalFilter(ptp,pn->un.bool.left) || EvalFilter(ptp,pn->un.bool.right));

    if (pn->op == NOT)
	return(!EvalFilter(ptp,pn->un.bool.left));

    return(EvalLeaf(ptp,pn));
}


Bool
PassesFilter(
    tcp_pair *ptp)
{
    Bool ret;

    ret = EvalFilter(ptp,filter_root);

    if (debug)
	printf("PassesFilter('%s<->%s') returns %s\n",
	       ptp->a_endpoint, ptp->b_endpoint,
	       ret?"TRUE":"FALSE");

    return(ret);
}


void
HelpFilter(void)
{
    fprintf(stderr,"\n\
Filter Expressions.....\n");
}


void
InstallFilter(
    struct filter_node *root)
{
    filter_root = root;
}

int
filter_getc(
    void *in_junk)
{
    static char *pinput = NULL;
    int ch;

    if (pinput == NULL)
	pinput = exprstr;

    if (*pinput == '\00')
	return(0);

    ch = *pinput++;

    return(ch);
}


