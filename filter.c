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
#include "filter_vars.h"


/* local routines */
static char *PrintConst(struct filter_node *pfn);
static char *PrintVar(struct filter_node *pfn);
static void EvalRelopUnsigned(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static void EvalRelopSigned(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static void EvalFilter(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static void EvalRelopString(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static void EvalVariable(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static void EvalConstant(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pfn);
static struct filter_node *LookupVar(char *varname, Bool fclient);


/* local globals */
static char *exprstr = NULL;
static struct filter_node *filter_root = NULL;

char*
Op2Str(
    enum optype op)
{
    switch (op) {
      case OP_AND:		return("AND");
      case OP_OR:		return("OR");
      case OP_GREATER:		return(">");
      case OP_GREATER_EQ:	return(">=");
      case OP_LESS:		return("<");
      case OP_LESS_EQ:		return("<=");
      case OP_EQUAL:		return("==");
      case OP_NEQUAL:		return("!=");
      default:			return("??");
    }
}




char*
Vartype2Str(
    enum vartype vartype)
{
    switch (vartype) {
      case V_BOOL:	return("V_BOOL");
      case V_CHAR:	return("V_CHAR");
      case V_INT:	return("V_INT");
      case V_LONG:	return("V_LONG");
      case V_SHORT:	return("V_SHORT");
      case V_STRING:	return("V_STRING");
      case V_UCHAR:	return("V_UCHAR");
      case V_UINT:	return("V_UINT");
      case V_ULONG:	return("V_ULONG");
      case V_USHORT:	return("V_USHORT");
#ifdef HAVE_LONG_LONG
      case V_LLONG:	return("V_LLONG");
      case V_ULLONG:	return("V_ULLONG");
#endif /* HAVE_LONG_LONG */
    }

    fprintf(stderr,"Vartype2Str: Internal error, unknown type %d\n",
	    vartype);
    exit(-1);
}



/**************************************************************/
/**************************************************************/
/**							     **/
/**  The following routines are all for Making filter trees  **/
/**							     **/
/**************************************************************/
/**************************************************************/

struct filter_node *
MakeUnaryNode(
    enum optype op,
    struct filter_node *pf)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));
    pfn->op = op;
    pfn->vartype = pf->vartype;

    pfn->un.unary.pf = pf;

    return(pfn);
}


struct filter_node *
MakeBinaryNode(
    enum optype op,
    struct filter_node *pf_left,
    struct filter_node *pf_right)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));
    pfn->op = op;
    pfn->vartype = V_BOOL;

    pfn->un.binary.left = pf_left;
    pfn->un.binary.right = pf_right;

    return(pfn);
}


struct filter_node *
MakeVarNode(
    char *varname)
{
    struct filter_node *pfn;

    if (strncasecmp(varname,"c_",2) == 0) {
	/* just client */
	pfn = LookupVar(varname+2,TRUE);
    } else if (strncasecmp(varname,"s_",2) == 0) {
	/* just server */
	pfn = LookupVar(varname+2,FALSE);
    } else {
	/* BOTH */
	fprintf(stderr,"Wildcard variables not suppored\n");
	exit(-1);
    }

    return(pfn);
}


struct filter_node *
MakeStringConstNode(
    char *val)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));

    pfn->vartype = V_STRING;
    pfn->un.constant.string = val;

    return(pfn);
}

struct filter_node *
MakeBoolConstNode(
    Bool val)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));

    pfn->vartype = V_BOOL;
    pfn->un.constant.bool = val;

    return(pfn);
}


struct filter_node *
MakeSignedConstNode(
    llong val)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));

    pfn->op = OP_CONSTANT;
    pfn->vartype = V_LLONG;
    pfn->un.constant.longint = val;

    return(pfn);
}


struct filter_node *
MakeUnsignedConstNode(
    u_llong val)
{
    struct filter_node *pfn;

    pfn = MallocZ(sizeof(struct filter_node));

    pfn->op = OP_CONSTANT;
    pfn->vartype = V_ULLONG;
    pfn->un.constant.u_longint = val;

    return(pfn);
}

/**************************************************************/
/**************************************************************/
/**							     **/
/** The folloing routines are all for PRINTING filter trees  **/
/**							     **/
/**************************************************************/
/**************************************************************/

static char *
PrintConst(
    struct filter_node *pfn)
{
    char buf[100];
    
    /* for constants */
    switch (pfn->vartype) {
      case V_ULLONG:	sprintf(buf,"ULLONG(%llu)",pfn->un.constant.u_longint); break;
      case V_LLONG:	sprintf(buf,"LLONG(%lld)", pfn->un.constant.longint); break;
      case V_STRING:	sprintf(buf,"STRING(%s)",pfn->un.constant.string); break;
      case V_BOOL:	sprintf(buf,"BOOL(%d)",  pfn->un.constant.bool); break;
      default: {
	  fprintf(stderr,"PrintConst: unknown constant type %d (%s)\n",
		  pfn->vartype, Vartype2Str(pfn->vartype));
	  exit(-1);
      }
    }

    /* small memory leak, but it's just done once for debugging... */
    return(strdup(buf));
}


static char *
PrintVar(
    struct filter_node *pfn)
{
    char buf[100];
    
    sprintf(buf,"VAR(%s,'%s',%d)",
	    Vartype2Str(pfn->vartype),
	    pfn->un.variable.name,
	    pfn->un.variable.offset);

    /* small memory leak, but it's just done once for debugging... */
    return(strdup(buf));
}





/**************************************************************/
/**************************************************************/
/**							     **/
/** The folloing routines are all for access from tcptrace   **/
/**							     **/
/**************************************************************/
/**************************************************************/

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

    return;
}




void
PrintFilter(
    struct filter_node *pfn)
{
    if (!pfn)
	return;

    switch(pfn->op) {
      case OP_CONSTANT:
	printf("%s", PrintConst(pfn));
	return;

      case OP_VARIABLE:
	printf("%s", PrintVar(pfn));
	return;

      case OP_AND:
      case OP_OR:
      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
	printf("(");
	PrintFilter(pfn->un.binary.left);
	printf(" %s ", Op2Str(pfn->op));
	PrintFilter(pfn->un.binary.right);
	printf(")");
	return;

      case OP_NOT:
	printf(" NOT(");
	PrintFilter(pfn->un.unary.pf);
	printf(")");
	return;

      default:
	fprintf(stderr,"PrintFilter: unknown op %d (%s)\n",
		pfn->op, Op2Str(pfn->op));
	exit(-1);
    }
}



static struct filter_node *
LookupVar(
    char *varname,
    Bool fclient)
{
    int i;
    struct filter_node *pfn;
    void *ptr;

    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pf = &filters[i];
	if (strcasecmp(varname,pf->varname) == 0) {
	    /* we found it */
	    pfn = MallocZ(sizeof(struct filter_node));
	    pfn->op = OP_VARIABLE;
	    pfn->vartype = pf->vartype;
	    pfn->un.variable.name = strdup(varname);
	    if (fclient)
		ptr = (void *)pf->cl_addr;
	    else
		ptr = (void *)pf->sv_addr;
	    pfn->un.variable.offset = ptr - (void *)&ptp_dummy;

	    return(pfn);
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
    struct filter_node *pfn)
{
    void *ptr;
    char *str;

    ptr = (char *)ptp + pfn->un.variable.offset;
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
    struct filter_node *pfn)
{
    void *ptr;

    ptr = (char *)ptp + pfn->un.variable.offset;

    switch (pfn->vartype) {
      case V_ULLONG: return(Ptr2Signed(V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Signed(V_ULONG,ptr));
      case V_UINT:   return(Ptr2Signed(V_UINT,ptr));
      case V_USHORT: return(Ptr2Signed(V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Signed(V_UCHAR,ptr));
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %s to signed\n",
		  Vartype2Str(pfn->vartype));
	  exit(-1);
      }
    }
}



static u_long
Var2Unsigned(
    tcp_pair *ptp,
    struct filter_node *pfn)
{
    void *ptr;

    ptr = (char *)ptp + pfn->un.variable.offset;

    switch (pfn->vartype) {
      case V_ULLONG: return(Ptr2Unsigned(V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Unsigned(V_ULONG,ptr));
      case V_UINT:   return(Ptr2Unsigned(V_UINT,ptr));
      case V_USHORT: return(Ptr2Unsigned(V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Unsigned(V_UCHAR,ptr));
      case V_BOOL:   return(Ptr2Unsigned(V_BOOL,ptr));
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %s to unsigned\n",
		  Vartype2Str(pfn->vartype));
	  exit(-1);
      }
    }
}


static u_llong
Const2Unsigned(
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_ULONG:	return((u_llong) pfn->un.constant.u_longint);
      case V_LONG:	return((u_llong) pfn->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d to unsigned\n",
		  pfn->vartype);
	  exit(-1);
      }
    }
}


static llong
Const2Signed(
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_ULONG:	return((llong) pfn->un.constant.u_longint);
      case V_LONG:	return((llong) pfn->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d to long\n",
		  pfn->vartype);
	  exit(-1);
      }
    }
}


/* evaluate a leaf-node UNSigned NUMBER */
static void
EvalRelopUnsigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    u_llong varl;
    u_llong varr;
    struct filter_res res;
    Bool ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pfn->un.binary.left);
    varl = res.val.u_longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pfn->un.binary.right);
    varr = res.val.u_longint;

    /* perform the operation */
    switch (pfn->op) {
      case OP_GREATER:    ret = (varl >  varr); break;
      case OP_GREATER_EQ: ret = (varl >= varr); break;
      case OP_LESS:	  ret = (varl <  varr); break;
      case OP_LESS_EQ:	  ret = (varl <= varr); break;
      case OP_EQUAL:	  ret = (varl == varr); break;
      case OP_NEQUAL:	  ret = (varl != varr); break;
      default: {
	  fprintf(stderr,"EvalUnsigned: unsupported binary op: %d (%s)\n",
		  pfn->op, Vartype2Str(pfn->op));
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_BOOL;
    pres->val.bool = ret;

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalUnsigned %llu %s %llu returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalUnsigned %lu %s %lu returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pfn->op), varr,
	       ret?"TRUE":"FALSE");


    return;
}



/* evaluate a leaf-node Signed NUMBER */
static void
EvalRelopSigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    llong varl;
    llong varr;
    struct filter_res res;
    Bool ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pfn->un.binary.left);
    varl = res.val.longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pfn->un.binary.right);
    varr = res.val.longint;

    switch (pfn->op) {
      case OP_GREATER:     ret = (varl >  varr); break;
      case OP_GREATER_EQ:  ret = (varl >= varr); break;
      case OP_LESS:        ret = (varl <  varr); break;
      case OP_LESS_EQ:     ret = (varl <= varr); break;
      case OP_EQUAL:       ret = (varl == varr); break;
      case OP_NEQUAL:      ret = (varl != varr); break;
      default: {
	  fprintf(stderr,"EvalSigned: internal error\n");
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_BOOL;
    pres->val.bool = ret;

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalSigned %lld %s %lld returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalSigned %ld %s %ld returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pfn->op), varr, 
	       ret?"TRUE":"FALSE");

    return;
}




/* evaluate a leaf-node string */
static void
EvalRelopString(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    char *varl;
    char *varr;
    struct filter_res res;
    Bool ret;
    int cmp;

    /* grab left hand side */
    EvalFilter(ptp,&res,pfn->un.binary.left);
    varl = res.val.string;

    /* grab right hand side */
    EvalFilter(ptp,&res,pfn->un.binary.right);
    varr = res.val.string;

    /* compare the strings */
    cmp = strcmp(varl,varr);
 
    switch (pfn->op) {
      case OP_GREATER:	   ret = (cmp >  0); break;
      case OP_GREATER_EQ:  ret = (cmp >= 0); break;
      case OP_LESS:	   ret = (cmp <  0); break;
      case OP_LESS_EQ:	   ret = (cmp <= 0); break;
      case OP_EQUAL:	   ret = (cmp == 0); break;
      case OP_NEQUAL:	   ret = (cmp != 0); break;
      default: {
	  fprintf(stderr,"EvalRelopString: unsupported operating %d (%s)\n",
		  pfn->op, Op2Str(pfn->op));
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_BOOL;
    pres->val.bool = ret;

    if (debug)
	printf("EvalString '%s' %s '%s' returns %s\n",
	       varl, Op2Str(pfn->op), varr, 
	       ret?"TRUE":"FALSE");

    return;
}


static void
EvalVariable(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_CHAR:	
      case V_SHORT:	
      case V_INT:	
      case V_LONG:	
#ifdef HAVE_LONG_LONG
      case V_LLONG:	
#endif /* HAVE_LONG_LONG */
	pres->vartype = V_LLONG;
	pres->val.u_longint = Var2Unsigned(ptp,pfn);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
#ifdef HAVE_LONG_LONG
      case V_ULLONG:	
#endif /* HAVE_LONG_LONG */
	pres->vartype = V_LLONG;
	pres->val.longint = Var2Signed(ptp,pfn);
	break;

      case V_STRING:	
	pres->vartype = V_STRING;
	pres->val.string = Var2String(ptp,pfn);
	break;

      case V_BOOL:
	pres->vartype = V_BOOL;
	pres->val.bool = (Var2Unsigned(ptp,pfn) != 0);
	break;

      default:
	fprintf(stderr,"EvalVariable: unknown var type %d (%s)\n",
		pfn->vartype, Vartype2Str(pfn->vartype));
    }

}



static void
EvalConstant(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_CHAR:	
      case V_SHORT:	
      case V_INT:	
      case V_LONG:	
#ifdef HAVE_LONG_LONG
      case V_LLONG:	
#endif /* HAVE_LONG_LONG */
	pres->vartype = V_LLONG;
	pres->val.u_longint = Var2Unsigned(ptp,pfn);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
#ifdef HAVE_LONG_LONG
      case V_ULLONG:	
#endif /* HAVE_LONG_LONG */
	pres->vartype = V_LLONG;
	pres->val.longint = Var2Signed(ptp,pfn);
	break;

      case V_STRING:	
	pres->vartype = V_STRING;
	pres->val.string = Var2String(ptp,pfn);
	break;

      case V_BOOL:
	pres->vartype = V_BOOL;
	pres->val.bool = (Var2Unsigned(ptp,pfn) != 0);
	break;

      default:
	fprintf(stderr,"EvalVariable: unknown var type %d (%s)\n",
		pfn->vartype, Vartype2Str(pfn->vartype));
    }

}
    



static void
EvalFilter(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    struct filter_res res;
    
    if (!pfn) {
	fprintf(stderr,"EvalFilter called with NULL!!!\n");
	exit(-1);
    }

    /* variables are easy */
    if (pfn->op == OP_VARIABLE) {
	EvalVariable(ptp,pres,pfn);
	return;
    }

    /* constants are easy */
    if (pfn->op == OP_CONSTANT) {
	EvalConstant(ptp,pres,pfn);
	return;
    }

    switch (pfn->op) {
      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
	if (pfn->un.binary.left->vartype == V_ULLONG) {
	    EvalRelopUnsigned(ptp,&res,pfn);
	    pres->vartype = V_BOOL;
	    pres->val.bool = res.val.bool;
	} else if (pfn->un.binary.left->vartype == V_LLONG) {
	    EvalRelopSigned(ptp,&res,pfn);
	    pres->vartype = V_BOOL;
	    pres->val.bool = res.val.bool;
	} else if (pfn->un.binary.left->vartype == V_STRING) {
	    EvalRelopString(ptp,&res,pfn);
	    pres->vartype = V_LLONG;
	    pres->val.longint = res.val.longint;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary operation %s not supported on data type %s\n",
		    Op2Str(pfn->op),Vartype2Str(pfn->un.binary.left->vartype));
	    exit(-1);
	}
	break;

      case OP_AND:
      case OP_OR:
	if (pfn->vartype == V_BOOL) {
	    struct filter_res res1;
	    struct filter_res res2;
	    Bool ret;
	    if (pfn->op == OP_OR) {
		EvalFilter(ptp,&res1,pfn->un.binary.left);
		EvalFilter(ptp,&res2,pfn->un.binary.right);
		ret = res1.val.bool || res2.val.bool;
	    } else {
		EvalFilter(ptp,&res1,pfn->un.binary.left);
		EvalFilter(ptp,&res2,pfn->un.binary.right);
		ret = res1.val.bool &&  res2.val.bool;
	    }
	    res.vartype = V_BOOL;
	    res.val.bool = ret;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary operation %s not supported on data type %s\n",
		    Op2Str(pfn->op),Vartype2Str(pfn->vartype));
	    exit(-1);
	}
	break;

      case OP_NOT:
	if (pfn->vartype == V_BOOL) {
	    EvalFilter(ptp,&res,pfn->un.unary.pf);
	    pres->vartype = V_BOOL;
	    pres->val.longint = !res.val.bool;
	} else {
	    fprintf(stderr,
		    "EvalFilter: unary operation %d (%s) not supported on data type %d (%s)\n",
		    pfn->op, Op2Str(pfn->op),
		    pfn->vartype, Vartype2Str(pfn->vartype));
	    exit(-1);
	}

      default:
	fprintf(stderr,
		"EvalFilter: operation %s not supported on data type %s\n",
		Op2Str(pfn->op),Vartype2Str(pfn->vartype));
	exit(-1);
    }

    /* set the answer */
    pres->vartype = V_BOOL;
    pres->val.bool = res.val.bool;

    return;
}




Bool
PassesFilter(
    tcp_pair *ptp)
{
    struct filter_res res;
    Bool ret;

    /* recurse down the tree */
    EvalFilter(ptp,&res,filter_root);
    ret = res.val.bool;

    if (debug)
	printf("PassesFilter('%s<->%s') returns %s\n",
	       ptp->a_endpoint, ptp->b_endpoint,
	       ret?"TRUE":"FALSE");

    return(ret);
}


void
HelpFilter(void)
{
    int i;
    fprintf(stderr,"Filter Variables:\n");


    fprintf(stderr,"\tvariable name         type\n");
    fprintf(stderr,"\t--------------------  ----------\n");
    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pf = &filters[i];

	fprintf(stderr,"\t%-20s  %s\n",
		pf->varname, Vartype2Str(pf->vartype));
		
    }
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


