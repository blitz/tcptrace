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
static char *PrintFilterInternal(struct filter_node *pfn);
static char *Res2Str(struct filter_res *pres);
static struct filter_node *MustBeType(enum vartype var_needed, struct filter_node *pf);
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
      case OP_PLUS:		return("+");
      case OP_MINUS:		return("-");
      case OP_TIMES:		return("*");
      case OP_DIVIDE:		return("/");
      default:			return("??");
    }
}




char*
Vartype2BStr(
    enum vartype vartype)
{
    switch (vartype) {
      case V_BOOL:	return("BOOL");
      case V_STRING:	return("STRING");

      case V_CHAR:	
      case V_FUNC:	
      case V_INT:	
      case V_LLONG:	
      case V_LONG:	
      case V_SHORT:	return("SIGNED");

      case V_UCHAR:	
      case V_UFUNC:	
      case V_UINT:	
      case V_ULLONG:	
      case V_ULONG:	
      case V_USHORT:	return("UNSIGNED");
    }

    fprintf(stderr,"Vartype2Str: Internal error, unknown type %d\n",
	    vartype);
    exit(-1);
}


char*
Vartype2Str(
    enum vartype vartype)
{
    switch (vartype) {
      case V_BOOL:	return("BOOL");
      case V_CHAR:	return("CHAR");
      case V_INT:	return("INT");
      case V_LONG:	return("LONG");
      case V_SHORT:	return("SHORT");
      case V_STRING:	return("STRING");
      case V_UCHAR:	return("UCHAR");
      case V_UINT:	return("UINT");
      case V_ULONG:	return("ULONG");
      case V_USHORT:	return("USHORT");
      case V_LLONG:	return("LLONG");
      case V_ULLONG:	return("ULLONG");
      case V_FUNC:	return("FUNC");
      case V_UFUNC:	return("UFUNC");
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

static struct filter_node *
MustBeType(
    enum vartype var_needed,
    struct filter_node *pf)
{
    /* if they match, we're done */
    if (pf->vartype == var_needed)
	return(pf);

    /* the only conversion we can do is unsigned to signed */
    if ((pf->vartype == V_ULLONG) && (var_needed == V_LLONG)) {
	struct filter_node *pf_new;

	pf_new = MakeUnaryNode(OP_SIGNED,pf);
	return(pf_new);
    }

    /* else it's an error */
    fprintf(stderr,"Filter expression should be type %s, but isn't: ",
	    Vartype2Str(var_needed));
    PrintFilter(pf);
    exit(-1);
}




struct filter_node *
MakeUnaryNode(
    enum optype op,
    struct filter_node *pf)
{
    struct filter_node *pfn;

    /* type checking */
    if (op == OP_NOT)
	pf = MustBeType(V_BOOL,pf);

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

    /* type checking */
    switch (op) {
      case OP_AND:
      case OP_OR:
	pf_left = MustBeType(V_BOOL,pf_left);
	pf_right = MustBeType(V_BOOL,pf_right);
	pfn->vartype = V_BOOL;
	break;

      case OP_PLUS:
      case OP_MINUS:
      case OP_TIMES:
      case OP_DIVIDE:
	if ((pf_left->vartype != V_LLONG) && (pf_left->vartype != V_ULLONG)) {
	    fprintf(stderr,"Arithmetic operator applied to non-number: ");
	    PrintFilter(pf_left);
	    exit(-1);
	}
	if ((pf_right->vartype != V_LLONG) && (pf_right->vartype != V_ULLONG)) {
	    fprintf(stderr,"Arithmetic operator applied to non-number: ");
	    PrintFilter(pf_right);
	    exit(-1);
	}

	/* else, they's both either signed or unsigned */
	if ((pf_left->vartype == V_LLONG) && (pf_right->vartype == V_ULLONG)) {
	    /* convert right to signed */
	    pf_right = MustBeType(V_LLONG,pf_right);
	} else if ((pf_left->vartype == V_ULLONG) && (pf_right->vartype == V_LLONG)) {
	    /* convert left to signed */
	    pf_left = MustBeType(V_LLONG,pf_left);
	}

	pfn->vartype = pf_left->vartype;
	break;

      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
	if ((pf_left->vartype != V_LLONG) && (pf_left->vartype != V_ULLONG)) {
	    fprintf(stderr,"Relational operator applied to non-number: ");
	    PrintFilter(pf_left);
	    exit(-1);
	}
	if ((pf_right->vartype != V_LLONG) && (pf_right->vartype != V_ULLONG)) {
	    fprintf(stderr,"Relational operator applied to non-number: ");
	    PrintFilter(pf_right);
	    exit(-1);
	}

	/* else, they's both either signed or unsigned */
	if ((pf_left->vartype == V_LLONG) && (pf_right->vartype == V_ULLONG)) {
	    /* convert right to signed */
	    pf_right = MustBeType(V_LLONG,pf_right);
	} else if ((pf_left->vartype == V_ULLONG) && (pf_right->vartype == V_LLONG)) {
	    /* convert left to signed */
	    pf_left = MustBeType(V_LLONG,pf_left);
	}

	pfn->vartype = V_BOOL;
	    
	break;

      default:
	fprintf(stderr,"MakeBinaryNode: invalid binary operand type %d (%s)\n",
		op, Op2Str(op));
	exit(-1);
    }
    

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
	fprintf(stderr,
		"Must specify either server (s_) or client (c_) for variable %s\n",
		varname);
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
      case V_ULLONG:
	if (debug)
	    sprintf(buf,"ULLONG(%llu)",pfn->un.constant.u_longint);
	else
	    sprintf(buf,"%llu",pfn->un.constant.u_longint);
	break;
      case V_LLONG:
	if (debug)
	    sprintf(buf,"LLONG(%lld)", pfn->un.constant.longint);
	else
	    sprintf(buf,"%lld", pfn->un.constant.longint);
	break;
      case V_STRING:
	if (debug)
	    sprintf(buf,"STRING(%s)",pfn->un.constant.string);
	else
	    sprintf(buf,"%s",pfn->un.constant.string);
	break;
      case V_BOOL:
	if (debug)
	    sprintf(buf,"BOOL(%s)",  pfn->un.constant.bool?"TRUE":"FALSE");
	else
	    sprintf(buf,"%s", pfn->un.constant.bool?"TRUE":"FALSE");
	break;
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


    if (debug)
	sprintf(buf,"VAR(%s,'%s%s',%d)",
		Vartype2Str(pfn->vartype),
		pfn->un.variable.fclient?"c_":"s_",
		pfn->un.variable.name,
		pfn->un.variable.offset);
    else
	sprintf(buf,"%s%s",
		pfn->un.variable.fclient?"c_":"s_",
		pfn->un.variable.name);

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
	printf("Output filter: %s\n", Filter2Str(filter_root));
    } else {
	/* parsing failed */
	fprintf(stderr,"Filter parsing failed\n");
	exit(-1);
    }

    return;
}

static char *
Res2Str(
    struct filter_res *pres)
{
    char buf[100];
    
    /* for constants */
    switch (pres->vartype) {
      case V_ULLONG:	sprintf(buf,"ULLONG(%llu)",pres->val.u_longint); break;
      case V_LLONG:	sprintf(buf,"LLONG(%lld)", pres->val.longint); break;
      case V_STRING:	sprintf(buf,"STRING(%s)",pres->val.string); break;
      case V_BOOL:	sprintf(buf,"BOOL(%s)",  pres->val.bool?"TRUE":"FALSE"); break;
      default: {
	  fprintf(stderr,"Res2Str: unknown constant type %d (%s)\n",
		  pres->vartype, Vartype2Str(pres->vartype));
	  exit(-1);
      }
    }

    /* small memory leak, but it's just done once for debugging... */
    return(strdup(buf));
}


void
PrintFilter(
    struct filter_node *pfn)
{
    printf("%s\n", PrintFilterInternal(pfn));
}


char *
Filter2Str(
    struct filter_node *pfn)
{
    return(PrintFilterInternal(pfn));
}


static char *
PrintFilterInternal(
    struct filter_node *pfn)
{
    /* I'm tolerating a memory leak here because it's mostly just for debugging */
    char buf[1024];

    if (!pfn)
	return("");

    switch(pfn->op) {
      case OP_CONSTANT:
	sprintf(buf,"%s", PrintConst(pfn));
	return(strdup(buf));

      case OP_VARIABLE:
	sprintf(buf,"%s", PrintVar(pfn));
	return(strdup(buf));

      case OP_AND:
      case OP_OR:
      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
      case OP_PLUS:
      case OP_MINUS:
      case OP_TIMES:
      case OP_DIVIDE:
	sprintf(buf,"(%s%s%s)",
		PrintFilterInternal(pfn->un.binary.left),
		Op2Str(pfn->op),
		PrintFilterInternal(pfn->un.binary.right));
	return(strdup(buf));

      case OP_NOT:
	sprintf(buf," NOT(%s)",
	       PrintFilterInternal(pfn->un.unary.pf));
	return(strdup(buf));

      case OP_SIGNED:
	sprintf(buf," SIGNED(%s)",
	       PrintFilterInternal(pfn->un.unary.pf));
	return(strdup(buf));

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
	    switch (pf->vartype) {
	      case V_CHAR:	
	      case V_INT:	
	      case V_LLONG:	
	      case V_LONG:	
	      case V_SHORT:	
	      case V_FUNC:	
		pfn->vartype = V_LLONG; /* we'll promote on the fly */
		break;
	      case V_UCHAR:	
	      case V_UINT:	
	      case V_ULLONG:	
	      case V_ULONG:	
	      case V_USHORT:	
	      case V_UFUNC:	
		pfn->vartype = V_ULLONG; /* we'll promote on the fly */
		break;
	      default:
		pfn->vartype = pf->vartype; 
	    }
	    pfn->un.variable.realtype = pf->vartype;
	    pfn->un.variable.name = strdup(varname);
	    if (fclient)
		ptr = (void *)pf->cl_addr;
	    else
		ptr = (void *)pf->sv_addr;
	    if ((pf->vartype == V_FUNC) || (pf->vartype == V_UFUNC))
		pfn->un.variable.offset = (u_int)ptr;
	    else
		pfn->un.variable.offset = ptr - (void *)&ptp_dummy;
	    pfn->un.variable.fclient = fclient;

	    return(pfn);
	}
    }

    /* not found */
    fprintf(stderr,"Variable \"%s\" not found\n", varname);
    exit(-1);
}

static u_llong
Ptr2Signed(
    tcp_pair *ptp,
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
    tcp_pair *ptp,
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
		  "Ptr2Unsigned: can't convert variable type %s to unsigned\n",
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

    switch (pfn->un.variable.realtype) {
      case V_LLONG: return(Ptr2Signed(ptp,V_LLONG,ptr));
      case V_LONG:  return(Ptr2Signed(ptp,V_LONG,ptr));
      case V_INT:   return(Ptr2Signed(ptp,V_INT,ptr));
      case V_SHORT: return(Ptr2Signed(ptp,V_SHORT,ptr));
      case V_CHAR:  return(Ptr2Signed(ptp,V_CHAR,ptr));
      case V_FUNC:
      {   /* call the function */
	  llong (*pfunc)(tcp_pair *ptp);
	  pfunc = (llong (*)(tcp_pair *))(pfn->un.variable.offset);
	  return((*pfunc)(ptp));
      }
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert variable type %s to signed\n",
		  Vartype2Str(pfn->un.variable.realtype));
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

    switch (pfn->un.variable.realtype) {
      case V_ULLONG: return(Ptr2Unsigned(ptp,V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Unsigned(ptp,V_ULONG,ptr));
      case V_UINT:   return(Ptr2Unsigned(ptp,V_UINT,ptr));
      case V_USHORT: return(Ptr2Unsigned(ptp,V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Unsigned(ptp,V_UCHAR,ptr));
      case V_BOOL:   return(Ptr2Unsigned(ptp,V_BOOL,ptr));
      case V_UFUNC:
      {   /* call the function */
	  u_llong (*pfunc)(tcp_pair *ptp);
	  pfunc = (u_llong (*)(tcp_pair *))(pfn->un.variable.offset);
	  return((*pfunc)(ptp));
      }
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert variable type %s to unsigned\n",
		  Vartype2Str(pfn->un.variable.realtype));
	  exit(-1);
      }
    }
}


static u_llong
Const2Unsigned(
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_ULLONG:	return((u_llong) pfn->un.constant.u_longint);
      case V_LLONG:	return((u_llong) pfn->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d (%s) to unsigned\n",
		  pfn->vartype, Vartype2Str(pfn->vartype));
	  exit(-1);
      }
    }
}


static llong
Const2Signed(
    struct filter_node *pfn)
{
    switch (pfn->vartype) {
      case V_ULLONG:	return((llong) pfn->un.constant.u_longint);
      case V_LLONG:	return((llong) pfn->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d (%s) to signed\n",
		  pfn->vartype, Vartype2Str(pfn->vartype));
	  exit(-1);
      }
    }
}


static void
EvalMathopUnsigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    u_llong varl;
    u_llong varr;
    struct filter_res res;
    u_llong ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pfn->un.binary.left);
    varl = res.val.u_longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pfn->un.binary.right);
    varr = res.val.u_longint;

    /* perform the operation */
    switch (pfn->op) {
      case OP_PLUS:	  ret = (varl + varr); break;
      case OP_MINUS:	  ret = (varl - varr); break;
      case OP_TIMES:	  ret = (varl * varr); break;
      case OP_DIVIDE:	  ret = (varl / varr); break;
      default: {
	  fprintf(stderr,"EvalMathodUnsigned: unsupported binary op: %d (%s)\n",
		  pfn->op, Vartype2Str(pfn->op));
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_ULLONG;
    pres->val.u_longint = ret;

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalMathopUnsigned %llu %s %llu returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalMathopUnsigned %lu %s %lu returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pfn->op), varr,
	       Res2Str(pres));


    return;
}



static void
EvalMathopSigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pfn)
{
    llong varl;
    llong varr;
    struct filter_res res;
    llong ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pfn->un.binary.left);
    varl = res.val.longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pfn->un.binary.right);
    varr = res.val.longint;

    /* perform the operation */
    switch (pfn->op) {
      case OP_PLUS:	  ret = (varl + varr); break;
      case OP_MINUS:	  ret = (varl - varr); break;
      case OP_TIMES:	  ret = (varl * varr); break;
      case OP_DIVIDE:	  ret = (varl / varr); break;
      default: {
	  fprintf(stderr,"EvalMathodSigned: unsupported binary op: %d (%s)\n",
		  pfn->op, Vartype2Str(pfn->op));
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_LLONG;
    pres->val.longint = ret;

    if (debug)
#ifdef HAVE_LONG_LONG
	printf("EvalMathopSigned %lld %s %lld returns %s\n",
#else /* HAVE_LONG_LONG */
	printf("EvalMathopSigned %ld %s %ld returns %s\n",
#endif /* HAVE_LONG_LONG */
	       varl, Op2Str(pfn->op), varr,
	       Res2Str(pres));


    return;
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
      case V_LLONG:	
	pres->vartype = V_LLONG;
	pres->val.u_longint = Var2Signed(ptp,pfn);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
      case V_ULLONG:	
	pres->vartype = V_ULLONG;
	pres->val.longint = Var2Unsigned(ptp,pfn);
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
      case V_LLONG:	
	pres->vartype = V_LLONG;
	pres->val.u_longint = Const2Signed(pfn);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
      case V_ULLONG:	
	pres->vartype = V_LLONG;
	pres->val.longint = Const2Unsigned(pfn);
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
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pfn->op, Op2Str(pfn->op),
		    pfn->vartype, Vartype2Str(pfn->vartype));
	    exit(-1);
	}
	break;

      case OP_PLUS:
      case OP_MINUS:
      case OP_TIMES:
      case OP_DIVIDE:
	if (pfn->un.binary.left->vartype == V_ULLONG) {
	    EvalMathopUnsigned(ptp,&res,pfn);
	    pres->vartype = V_ULLONG;
	    pres->val.u_longint = res.val.u_longint;
	} else if (pfn->un.binary.left->vartype == V_LLONG) {
	    EvalMathopSigned(ptp,&res,pfn);
	    pres->vartype = V_LLONG;
	    pres->val.longint = res.val.longint;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pfn->op, Op2Str(pfn->op),
		    pfn->vartype, Vartype2Str(pfn->vartype));
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
	    pres->vartype = V_BOOL;
	    pres->val.bool = ret;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pfn->op, Op2Str(pfn->op),
		    pfn->vartype, Vartype2Str(pfn->vartype));
	    exit(-1);
	}
	break;

      case OP_NOT:
	if (pfn->vartype == V_BOOL) {
	    EvalFilter(ptp,&res,pfn->un.unary.pf);
	    pres->vartype = V_BOOL;
	    pres->val.bool = !res.val.bool;
	} else {
	    fprintf(stderr,
		    "EvalFilter: unary operation %d (%s) not supported on data type %d (%s)\n",
		    pfn->op, Op2Str(pfn->op),
		    pfn->vartype, Vartype2Str(pfn->vartype));
	    exit(-1);
	}
	break;

      default:
	fprintf(stderr,
		"EvalFilter: operation %d (%s) not supported on data type %d (%s)\n",
		pfn->op,Op2Str(pfn->op),
		pfn->vartype,Vartype2Str(pfn->vartype));
	exit(-1);
    }

    if (debug)
	printf("EvalFilter('%s') returns %s\n",
	       Filter2Str(pfn),Res2Str(pres));

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


    fprintf(stderr,"\tvariable name        type       description\n");
    fprintf(stderr,"\t------------------   --------   -----------------------\n");
    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pf = &filters[i];

	fprintf(stderr,"\t%-18s   %-8s   %s\n",
		pf->varname, Vartype2BStr(pf->vartype),pf->descr);
    }
    fprintf(stderr,"\n\
Filter Syntax:\n\
  numbers:\n\
     variables:\n\
	anything from the above table with a prefix of either 'c_' meaning\n\
        the one for the Client or 's_' meaning the value for the Server\n\
     constant:\n\
	strings:	anything in double quotes\n\
	booleans:	TRUE FALSE\n\
	numbers:	signed or unsigned constants\n\
  arithmetic operations: \n\
     any of the operators + - * / \n\
     performed on strings of 'numbers'.  Normal operator precedence\n\
	 is maintained (or use parens)\n\
  relational operators\n\
     any of < > = != >= <= applied to 'numbers'\n\
  boolean operators\n\
     any AND OR applied to the above\n\
  misc\n\
     can have parens\n\
     can use NOT(expr)\n\
     you'll probably need to put the expression in single quotes\n\
     matched connection numbers are saved in file %s for later processing
	with '-o%s' (for graphing, for example)
Examples
  tcptrace '-fc_packets>10' file
  tcptrace '-fc_packets>10 OR s_packets>10 ' file
  tcptrace '-f c_packets+1 > s_packets ' file
", PASS_FILTER_FILENAME, PASS_FILTER_FILENAME);
}


void
InstallFilter(
    struct filter_node *root)
{
    /* result MUST be boolean */
    if (root->vartype != V_BOOL) {
	fprintf(stderr,"Filter expression is not boolean: %s\n",
		Filter2Str(root));
	exit(-1);
    }
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

    if (*pinput == '\00') {
	static int doneyet = 0;
	if (++doneyet>1)
	    return(0);
	else
	    return('\n');
    }

    ch = *pinput++;

    return(ch);
}




/**************************************************************/
/**************************************************************/
/**							     **/
/**  The following routines are for calculated values        **/
/**							     **/
/**************************************************************/
/**************************************************************/
static u_llong
VFuncTput(
    tcb *ptcb)
{
    tcp_pair *ptp = ptcb->ptp;
    u_llong tput;
    double etime;
    etime = elapsed(ptp->first_time,ptp->last_time);

    etime /= 1000000.0;  /* convert to seconds */

    if (etime == 0.0)
	return(0);

    tput = (u_llong)((double)(ptcb->data_bytes-ptcb->rexmit_bytes) / etime);

    if (debug)
	printf("VFuncTput(ptcb) = %llu\n", tput);

    return(tput);
}

u_llong
VFuncClntTput(
    tcp_pair *ptp)
{
    return(VFuncTput(&ptp->a2b));
}

u_llong
VFuncServTput(
    tcp_pair *ptp)
{
    return(VFuncTput(&ptp->a2b));
}

