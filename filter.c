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
static char const copyright[] =
    "@(#)Copyright (c) 1999 -- Shawn Ostermann -- Ohio University.  All rights reserved.\n";
static char const rcsid[] =
    "@(#)$Header$";


#include <stdio.h>
#include <stdarg.h>

#include "tcptrace.h"
#include "filter.h"
#include "filter_vars.h"


/* local routines */
static char *PrintConst(struct filter_node *pf);
static char *PrintVar(struct filter_node *pf);
static void EvalRelopUnsigned(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalRelopSigned(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalRelopIpaddr(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalFilter(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalRelopString(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalVariable(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static void EvalConstant(tcp_pair *ptp, struct filter_res *pres, struct filter_node *pf);
static char *PrintFilterInternal(struct filter_node *pf);
static char *Res2Str(struct filter_res *pres);
static struct filter_node *MustBeType(enum vartype var_needed, struct filter_node *pf);
static struct filter_node *LookupVar(char *varname, Bool fclient);
static void HelpFilterVariables(void);


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
      case OP_MOD:		return("%");
      case OP_BAND:		return("&");
      case OP_BOR:		return("|");
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

      case V_IPADDR:	return("IPADDR");
    }

    fprintf(stderr,"Vartype2BStr: Internal error, unknown type %d\n",
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
      case V_IPADDR:	return("IPADDR");
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
    struct filter_node *pf_in)
{
    struct filter_node *pf_ret = NULL;
    struct filter_node *pf1;

    /* walk everybody on the list and copy */
    for (pf1 = pf_in; pf1; pf1=pf1->next_var) {
	struct filter_node *pf_new;

	/* type checking */
	if (op == OP_NOT)
	    pf_in = MustBeType(V_BOOL,pf_in);

	pf_new = MallocZ(sizeof(struct filter_node));
	pf_new->op = op;
	pf_new->vartype = pf1->vartype;
	pf_new->un.unary.pf = pf1;

	/* add to the linked list of unaries */
	if (pf_ret == NULL) {
	    pf_ret = pf_new;
	} else {
	    pf_new->next_var = pf_ret;
	    pf_ret = pf_new;
	}
    }

    return(pf_ret);
}



static struct filter_node *
MakeDisjunction(
    struct filter_node *left,
    struct filter_node *right)
{
    struct filter_node *pf;

    /* construct a high-level OR to hook them together */
    pf = MallocZ(sizeof(struct filter_node));
    pf->op = OP_OR;
    pf->vartype = V_BOOL;

    /* hook the two opnodes together */
    pf->un.binary.left = left;
    pf->un.binary.right = right;

    /* return the OR node */
    return(pf);
}


static struct filter_node *
MakeConjunction(
    struct filter_node *left,
    struct filter_node *right)
{
    struct filter_node *pf;

    /* construct a high-level AND to hook them together */
    pf = MallocZ(sizeof(struct filter_node));
    pf->op = OP_AND;
    pf->vartype = V_BOOL;

    /* hook the two opnodes together */
    pf->un.binary.left = left;
    pf->un.binary.right = right;

    /* return the OR node */
    return(pf);
}


static struct filter_node *
MakeOneBinaryNode(
    enum optype op,
    struct filter_node *pf_left,
    struct filter_node *pf_right)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));
    pf->op = op;

    /* type checking */
    switch (op) {
      case OP_AND:
      case OP_OR:
	pf_left = MustBeType(V_BOOL,pf_left);
	pf_right = MustBeType(V_BOOL,pf_right);
	pf->vartype = V_BOOL;
	break;

      case OP_PLUS:
      case OP_MINUS:
      case OP_TIMES:
      case OP_DIVIDE:
      case OP_MOD:
      case OP_BAND:
      case OP_BOR:
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

	pf->vartype = pf_left->vartype;
	break;

      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
	/* IP addresses are special case */
	if ((pf_left->vartype == V_IPADDR) ||
	    (pf_right->vartype == V_IPADDR)) {
	    /* must BOTH be addresses */
	    if ((pf_left->vartype != V_IPADDR) ||
		(pf_right->vartype != V_IPADDR)) {
		fprintf(stderr,
			"IPaddreses can only be compared with each other: ");
		PrintFilter(pf);
		exit(-1);
	    }
	    pf->vartype = V_BOOL;
	    break;
	}

	/* ... else, normal numeric stuff */
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

	pf->vartype = V_BOOL;
	    
	break;

      default:
	fprintf(stderr,"MakeBinaryNode: invalid binary operand type %d (%s)\n",
		op, Op2Str(op));
	exit(-1);
    }

    /* attach the children */
    pf->un.binary.left = pf_left;
    pf->un.binary.right = pf_right;

    return(pf);
}




struct filter_node *
MakeBinaryNode(
    enum optype op,
    struct filter_node *pf_left,
    struct filter_node *pf_right)
{
    struct filter_node *pf_ret = NULL;
    struct filter_node *pf1;
    struct filter_node *pf2;

    for (pf1 = pf_left; pf1; pf1=pf1->next_var) {
	for (pf2 = pf_right; pf2; pf2=pf2->next_var) {
	    struct filter_node *pf_new;
	    /* make one copy */
	    pf_new = MakeOneBinaryNode(op,pf1,pf2);
	    if ((pf1->conjunction) || (pf2->conjunction))
		pf_new->conjunction = TRUE;

	    if (debug>1)
		printf("MakeBinaryNode: made %s (%c)\n",
		       Filter2Str(pf_new),
		       pf_new->conjunction?'c':'d');

	    /* hook together as appropriate */
	    switch (op) {
	      case OP_PLUS:
	      case OP_MINUS:
	      case OP_TIMES:
	      case OP_DIVIDE:
	      case OP_MOD:
	      case OP_BAND:
	      case OP_BOR:
		/* just keep a list */
		if (pf_ret == NULL) {
		    pf_ret = pf_new;
		} else {
		    pf_new->next_var = pf_ret;
		    pf_ret = pf_new;
		}
		break;

	      case OP_AND:
	      case OP_OR:
	      case OP_EQUAL:
	      case OP_NEQUAL:
	      case OP_GREATER:
	      case OP_GREATER_EQ:
	      case OP_LESS:
	      case OP_LESS_EQ:
		/* terminate the wildcard list by making OR nodes or AND nodes*/
		if (pf_ret == NULL)
		    pf_ret = pf_new;
		else {
		    if ((pf1->conjunction) || (pf2->conjunction))
			pf_ret = MakeConjunction(pf_ret,pf_new);
		    else
			pf_ret = MakeDisjunction(pf_ret,pf_new);
		}
		break;

	      default:
		fprintf(stderr,"MakeBinaryNode: invalid binary operand type %d (%s)\n",
			op, Op2Str(op));
		exit(-1);
	    }

	}
    }

    return(pf_ret);
}


struct filter_node *
MakeVarNode(
    char *varname)
{
    struct filter_node *pf;

    if (strncasecmp(varname,"c_",2) == 0) {
	/* just client */
	pf = LookupVar(varname+2,TRUE);
    } else if (strncasecmp(varname,"s_",2) == 0) {
	/* just server */
	pf = LookupVar(varname+2,FALSE);
    } else if (strncasecmp(varname,"b_",2) == 0) {
	/* they want a CONjunction, look up BOTH and return a list */
	pf = LookupVar(varname+2,TRUE);/* client */
	pf->next_var = LookupVar(varname+2,FALSE); /* server */
	pf->conjunction = pf->next_var->conjunction = TRUE;
    } else if (strncasecmp(varname,"e_",2) == 0) {
	/* they want a DISjunction, look up BOTH and return a list */
	pf = LookupVar(varname+2,TRUE);/* client */
	pf->next_var = LookupVar(varname+2,FALSE); /* server */
    } else {
	/* look up BOTH and return a list (same as e_) */
	pf = LookupVar(varname,TRUE);/* client */
	pf->next_var = LookupVar(varname,FALSE); /* server */
    }

    return(pf);
}


struct filter_node *
MakeStringConstNode(
    char *val)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));

    pf->vartype = V_STRING;
    pf->un.constant.string = val;

    return(pf);
}

struct filter_node *
MakeBoolConstNode(
    Bool val)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));

    pf->vartype = V_BOOL;
    pf->un.constant.bool = val;

    return(pf);
}


struct filter_node *
MakeSignedConstNode(
    llong val)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));

    pf->op = OP_CONSTANT;
    pf->vartype = V_LLONG;
    pf->un.constant.longint = val;

    return(pf);
}


struct filter_node *
MakeUnsignedConstNode(
    u_llong val)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));

    pf->op = OP_CONSTANT;
    pf->vartype = V_ULLONG;
    pf->un.constant.u_longint = val;

    return(pf);
}

struct filter_node *
MakeIPaddrConstNode(
    ipaddr *pipaddr)
{
    struct filter_node *pf;

    pf = MallocZ(sizeof(struct filter_node));

    pf->op = OP_CONSTANT;
    pf->vartype = V_IPADDR;
    pf->un.constant.pipaddr = pipaddr;

    return(pf);
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
    struct filter_node *pf)
{
    char buf[100];
    
    /* for constants */
    switch (pf->vartype) {
      case V_ULLONG:
	if (debug)
	    sprintf(buf,"ULLONG(%llu)",
		    pf->un.constant.u_longint);
	else
	    sprintf(buf,"%llu",pf->un.constant.u_longint);
	break;
      case V_LLONG:
	if (debug)
	    sprintf(buf,"LLONG(%lld)", pf->un.constant.longint);
	else
	    sprintf(buf,"%lld", pf->un.constant.longint);
	break;
      case V_STRING:
	if (debug)
	    sprintf(buf,"STRING(%s)",pf->un.constant.string);
	else
	    sprintf(buf,"%s",pf->un.constant.string);
	break;
      case V_BOOL:
	if (debug)
	    sprintf(buf,"BOOL(%s)",  BOOL2STR(pf->un.constant.bool));
	else
	    sprintf(buf,"%s", BOOL2STR(pf->un.constant.bool));
	break;
      case V_IPADDR:
	if (debug)
	    sprintf(buf,"IPADDR(%s)", HostAddr(*pf->un.constant.pipaddr));
	else
	    sprintf(buf,"%s", HostAddr(*pf->un.constant.pipaddr));
	break;
      default: {
	    fprintf(stderr,"PrintConst: unknown constant type %d (%s)\n",
		    pf->vartype, Vartype2Str(pf->vartype));
	    exit(-1);
	}
    }

    /* small memory leak, but it's just done once for debugging... */
    return(strdup(buf));
}


static char *
PrintVar(
    struct filter_node *pf)
{
    char buf[100];


    if (debug)
	sprintf(buf,"VAR(%s,'%s%s',%d,%c)",
		Vartype2Str(pf->vartype),
		pf->un.variable.fclient?"c_":"s_",
		pf->un.variable.name,
		pf->un.variable.offset,
		pf->conjunction?'c':'d');
    else
	sprintf(buf,"%s%s",
		pf->un.variable.fclient?"c_":"s_",
		pf->un.variable.name);

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
	filtyydebug = 1;

    if (filtyyparse() == 0) {
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
      case V_BOOL:	sprintf(buf,"BOOL(%s)",  BOOL2STR(pres->val.bool)); break;
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
    struct filter_node *pf)
{
    printf("%s\n", PrintFilterInternal(pf));
}


char *
Filter2Str(
    struct filter_node *pf)
{
    return(PrintFilterInternal(pf));
}


static char *
PrintFilterInternal(
    struct filter_node *pf)
{
    /* I'm tolerating a memory leak here because it's mostly just for debugging */
    char buf[1024];

    if (!pf)
	return("");

    switch(pf->op) {
      case OP_CONSTANT:
	sprintf(buf,"%s", PrintConst(pf));
	return(strdup(buf));

      case OP_VARIABLE:
	sprintf(buf,"%s", PrintVar(pf));
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
      case OP_MOD:
      case OP_BAND:
      case OP_BOR:
	sprintf(buf,"(%s%s%s)",
		PrintFilterInternal(pf->un.binary.left),
		Op2Str(pf->op),
		PrintFilterInternal(pf->un.binary.right));
	return(strdup(buf));

      case OP_NOT:
	sprintf(buf," NOT(%s)",
	       PrintFilterInternal(pf->un.unary.pf));
	return(strdup(buf));

      case OP_SIGNED:
	sprintf(buf," SIGNED(%s)",
	       PrintFilterInternal(pf->un.unary.pf));
	return(strdup(buf));

      default:
	fprintf(stderr,"PrintFilter: unknown op %d (%s)\n",
		pf->op, Op2Str(pf->op));
	exit(-1);
    }
}



static struct filter_node *
LookupVar(
    char *varname,
    Bool fclient)
{
    int i;
    struct filter_node *pf;
    void *ptr;

    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pfl = &filters[i];
	if (strcasecmp(varname,pfl->varname) == 0) {
	    /* we found it */
	    pf = MallocZ(sizeof(struct filter_node));
	    pf->op = OP_VARIABLE;
	    switch (pfl->vartype) {
	      case V_CHAR:	
	      case V_INT:	
	      case V_LLONG:	
	      case V_LONG:	
	      case V_SHORT:	
	      case V_FUNC:	
		pf->vartype = V_LLONG; /* we'll promote on the fly */
		break;
	      case V_UCHAR:	
	      case V_UINT:	
	      case V_ULLONG:	
	      case V_ULONG:	
	      case V_USHORT:	
	      case V_UFUNC:	
		pf->vartype = V_ULLONG; /* we'll promote on the fly */
		break;
	      case V_BOOL:	
		pf->vartype = V_BOOL;
		break;
	      case V_IPADDR:	
		pf->vartype = V_IPADDR;
		break;
	      default:
		pf->vartype = pf->vartype; 
	    }
	    pf->un.variable.realtype = pfl->vartype;
	    pf->un.variable.name = strdup(varname);
	    if (fclient)
		ptr = (void *)pfl->cl_addr;
	    else
		ptr = (void *)pfl->sv_addr;
	    if ((pfl->vartype == V_FUNC) || (pfl->vartype == V_UFUNC))
		pf->un.variable.offset = (u_int)ptr;
	    else
		pf->un.variable.offset = (char *)ptr - (char *)&ptp_dummy;
	    pf->un.variable.fclient = fclient;

	    return(pf);
	}
    }

    /* not found */
    fprintf(stderr,"Variable \"%s\" not found\n", varname);

    HelpFilterVariables();
    
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
    struct filter_node *pf)
{
    void *ptr;
    char *str;

    ptr = (char *)ptp + pf->un.variable.offset;
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
    struct filter_node *pf)
{
    void *ptr;

    ptr = (char *)ptp + pf->un.variable.offset;

    switch (pf->un.variable.realtype) {
      case V_LLONG: return(Ptr2Signed(ptp,V_LLONG,ptr));
      case V_LONG:  return(Ptr2Signed(ptp,V_LONG,ptr));
      case V_INT:   return(Ptr2Signed(ptp,V_INT,ptr));
      case V_SHORT: return(Ptr2Signed(ptp,V_SHORT,ptr));
      case V_CHAR:  return(Ptr2Signed(ptp,V_CHAR,ptr));
      case V_FUNC:
      {   /* call the function */
	  llong (*pfunc)(tcp_pair *ptp);
	  pfunc = (llong (*)(tcp_pair *))(pf->un.variable.offset);
	  return((*pfunc)(ptp));
      }
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert variable type %s to signed\n",
		  Vartype2Str(pf->un.variable.realtype));
	  exit(-1);
      }
    }
}


static ipaddr *
Var2Ipaddr(
    tcp_pair *ptp,
    struct filter_node *pf)
{
    void *ptr;

    ptr = (char *)ptp + pf->un.variable.offset;

    switch (pf->un.variable.realtype) {
      case V_IPADDR: return(ptr);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert variable type %s to ipaddr\n",
		  Vartype2Str(pf->un.variable.realtype));
	  exit(-1);
      }
    }
}



static u_long
Var2Unsigned(
    tcp_pair *ptp,
    struct filter_node *pf)
{
    void *ptr;

    ptr = (char *)ptp + pf->un.variable.offset;

    switch (pf->un.variable.realtype) {
      case V_ULLONG: return(Ptr2Unsigned(ptp,V_ULLONG,ptr));
      case V_ULONG:  return(Ptr2Unsigned(ptp,V_ULONG,ptr));
      case V_UINT:   return(Ptr2Unsigned(ptp,V_UINT,ptr));
      case V_USHORT: return(Ptr2Unsigned(ptp,V_USHORT,ptr));
      case V_UCHAR:  return(Ptr2Unsigned(ptp,V_UCHAR,ptr));
      case V_BOOL:   return(Ptr2Unsigned(ptp,V_BOOL,ptr));
      case V_UFUNC:
      {   /* call the function */
	  u_llong (*pfunc)(tcp_pair *ptp);
	  pfunc = (u_llong (*)(tcp_pair *))(pf->un.variable.offset);
	  return((*pfunc)(ptp));
      }
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert variable type %s to unsigned\n",
		  Vartype2Str(pf->un.variable.realtype));
	  exit(-1);
      }
    }
}


static u_llong
Const2Unsigned(
    struct filter_node *pf)
{
    switch (pf->vartype) {
      case V_ULLONG:	return((u_llong) pf->un.constant.u_longint);
      case V_LLONG:	return((u_llong) pf->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d (%s) to unsigned\n",
		  pf->vartype, Vartype2Str(pf->vartype));
	  exit(-1);
      }
    }
}


static llong
Const2Signed(
    struct filter_node *pf)
{
    switch (pf->vartype) {
      case V_ULLONG:	return((llong) pf->un.constant.u_longint);
      case V_LLONG:	return((llong) pf->un.constant.longint);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d (%s) to signed\n",
		  pf->vartype, Vartype2Str(pf->vartype));
	  exit(-1);
      }
    }
}


static ipaddr *
Const2Ipaddr(
    struct filter_node *pf)
{
    switch (pf->vartype) {
      case V_IPADDR:	return(pf->un.constant.pipaddr);
      default: {
	  fprintf(stderr,
		  "Filter eval error, can't convert constant type %d (%s) to ipaddr\n",
		  pf->vartype, Vartype2Str(pf->vartype));
	  exit(-1);
      }
    }
}


static void
EvalMathopUnsigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    u_llong varl;
    u_llong varr;
    struct filter_res res;
    u_llong ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pf->un.binary.left);
    varl = res.val.u_longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pf->un.binary.right);
    varr = res.val.u_longint;

    /* perform the operation */
    switch (pf->op) {
      case OP_PLUS:	  ret = (varl + varr); break;
      case OP_MINUS:	  ret = (varl - varr); break;
      case OP_TIMES:	  ret = (varl * varr); break;
      case OP_DIVIDE:	  ret = (varl / varr); break;
      case OP_MOD:	  ret = (varl % varr); break;
      case OP_BAND:	  ret = (varl & varr); break;
      case OP_BOR:	  ret = (varl | varr); break;
      default: {
	  fprintf(stderr,"EvalMathodUnsigned: unsupported binary op: %d (%s)\n",
		  pf->op, Op2Str(pf->op));
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
	       varl, Op2Str(pf->op), varr,
	       Res2Str(pres));


    return;
}



static void
EvalMathopSigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    llong varl;
    llong varr;
    struct filter_res res;
    llong ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pf->un.binary.left);
    varl = res.val.longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pf->un.binary.right);
    varr = res.val.longint;

    /* perform the operation */
    switch (pf->op) {
      case OP_PLUS:	  ret = (varl + varr); break;
      case OP_MINUS:	  ret = (varl - varr); break;
      case OP_TIMES:	  ret = (varl * varr); break;
      case OP_DIVIDE:	  ret = (varl / varr); break;
      case OP_MOD:	  ret = (varl % varr); break;
      case OP_BAND:	  ret = (varl & varr); break;
      case OP_BOR:	  ret = (varl | varr); break;
      default: {
	  fprintf(stderr,"EvalMathodSigned: unsupported binary op: %d (%s)\n",
		  pf->op, Op2Str(pf->op));
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
	       varl, Op2Str(pf->op), varr,
	       Res2Str(pres));


    return;
}



/* evaluate a leaf-node UNSigned NUMBER */
static void
EvalRelopUnsigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    u_llong varl;
    u_llong varr;
    struct filter_res res;
    Bool ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pf->un.binary.left);
    varl = res.val.u_longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pf->un.binary.right);
    varr = res.val.u_longint;

    /* perform the operation */
    switch (pf->op) {
      case OP_GREATER:    ret = (varl >  varr); break;
      case OP_GREATER_EQ: ret = (varl >= varr); break;
      case OP_LESS:	  ret = (varl <  varr); break;
      case OP_LESS_EQ:	  ret = (varl <= varr); break;
      case OP_EQUAL:	  ret = (varl == varr); break;
      case OP_NEQUAL:	  ret = (varl != varr); break;
      default: {
	  fprintf(stderr,"EvalUnsigned: unsupported binary op: %d (%s)\n",
		  pf->op, Op2Str(pf->op));
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
	       varl, Op2Str(pf->op), varr,
	       BOOL2STR(ret));


    return;
}



/* evaluate a leaf-node Signed NUMBER */
static void
EvalRelopSigned(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    llong varl;
    llong varr;
    struct filter_res res;
    Bool ret;

    /* grab left hand side */
    EvalFilter(ptp,&res,pf->un.binary.left);
    varl = res.val.longint;

    /* grab right hand side */
    EvalFilter(ptp,&res,pf->un.binary.right);
    varr = res.val.longint;

    switch (pf->op) {
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
	       varl, Op2Str(pf->op), varr, 
	       BOOL2STR(ret));

    return;
}




/* evaluate a leaf-node IPaddress */
static void
EvalRelopIpaddr(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
     ipaddr *varl;
     ipaddr *varr;
     struct filter_res res;
     Bool ret;

     /* grab left hand side */
     EvalFilter(ptp,&res,pf->un.binary.left);
     varl = res.val.pipaddr;

     /* grab right hand side */
     EvalFilter(ptp,&res,pf->un.binary.right);
     varr = res.val.pipaddr;

     /* always evaluates FALSE unless both same type */
     if (varl->addr_vers != varr->addr_vers) {
	 if (debug) {
	     printf("EvalIpaddr %s", HostAddr(*varl));
	     printf("%s fails, different addr types\n",
		    HostAddr(*varr));
	 }
	 ret = FALSE;
     } else {
	 int i;
	 int len = (varl->addr_vers == 4)?4:6;
	 u_char *left = (char *)&varl->un.ip4;
	 u_char *right = (char *)&varr->un.ip4;
	 int result = 0;

	 for (i=0; (result == 0) && (i < len); ++i) {
	     if (left[i] < right[i]) {
		 result = -1;
	     } else if (left[i] > right[i]) {
		 result = 1;
	     }
	     /* else ==, keep going */
	 }

	 switch (pf->op) {
	   case OP_GREATER:     ret = (result >  0); break;
	   case OP_GREATER_EQ:  ret = (result >= 0); break;
	   case OP_LESS:        ret = (result <  0); break;
	   case OP_LESS_EQ:     ret = (result <= 0); break;
	   case OP_EQUAL:       ret = (result == 0); break;
	   case OP_NEQUAL:      ret = (result != 0); break;
	   default: {
	       fprintf(stderr,"EvalIpaddr: internal error\n");
	       exit(-1);
	   }
	 }
     }

     /* fill in the answer */
     pres->vartype = V_BOOL;
     pres->val.bool = ret;

     if (debug) {
	 printf("EvalIpaddr %s %s", HostAddr(*varl), Op2Str(pf->op));
	 printf("%s returns %s\n", HostAddr(*varr), BOOL2STR(ret));
     }

     return;
 }




/* evaluate a leaf-node string */
static void
EvalRelopString(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    char *varl;
    char *varr;
    struct filter_res res;
    Bool ret;
    int cmp;

    /* grab left hand side */
    EvalFilter(ptp,&res,pf->un.binary.left);
    varl = res.val.string;

    /* grab right hand side */
    EvalFilter(ptp,&res,pf->un.binary.right);
    varr = res.val.string;

    /* compare the strings */
    cmp = strcmp(varl,varr);
 
    switch (pf->op) {
      case OP_GREATER:	   ret = (cmp >  0); break;
      case OP_GREATER_EQ:  ret = (cmp >= 0); break;
      case OP_LESS:	   ret = (cmp <  0); break;
      case OP_LESS_EQ:	   ret = (cmp <= 0); break;
      case OP_EQUAL:	   ret = (cmp == 0); break;
      case OP_NEQUAL:	   ret = (cmp != 0); break;
      default: {
	  fprintf(stderr,"EvalRelopString: unsupported operating %d (%s)\n",
		  pf->op, Op2Str(pf->op));
	  exit(-1);
      }
    }

    /* fill in the answer */
    pres->vartype = V_BOOL;
    pres->val.bool = ret;

    if (debug)
	printf("EvalString '%s' %s '%s' returns %s\n",
	       varl, Op2Str(pf->op), varr, 
	       BOOL2STR(ret));

    return;
}


static void
EvalVariable(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    switch (pf->vartype) {
      case V_CHAR:	
      case V_SHORT:	
      case V_INT:	
      case V_LONG:	
      case V_LLONG:	
	pres->vartype = V_LLONG;
	pres->val.u_longint = Var2Signed(ptp,pf);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
      case V_ULLONG:	
	pres->vartype = V_ULLONG;
	pres->val.longint = Var2Unsigned(ptp,pf);
	break;

      case V_STRING:	
	pres->vartype = V_STRING;
	pres->val.string = Var2String(ptp,pf);
	break;

      case V_BOOL:
	pres->vartype = V_BOOL;
	pres->val.bool = (Var2Unsigned(ptp,pf) != 0);
	break;

      case V_IPADDR:
	pres->vartype = V_IPADDR;
	pres->val.pipaddr = Var2Ipaddr(ptp,pf);
	break;

      default:
	fprintf(stderr,"EvalVariable: unknown var type %d (%s)\n",
		pf->vartype, Vartype2Str(pf->vartype));
	exit(-1);
    }

}



static void
EvalConstant(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    switch (pf->vartype) {
      case V_CHAR:	
      case V_SHORT:	
      case V_INT:	
      case V_LONG:	
      case V_LLONG:	
	pres->vartype = V_LLONG;
	pres->val.u_longint = Const2Signed(pf);
	break;

      case V_UCHAR:	
      case V_USHORT:	
      case V_UINT:	
      case V_ULONG:	
      case V_ULLONG:	
	pres->vartype = V_LLONG;
	pres->val.longint = Const2Unsigned(pf);
	break;

      case V_STRING:	
	pres->vartype = V_STRING;
	pres->val.string = Var2String(ptp,pf);
	break;

      case V_BOOL:
	pres->vartype = V_BOOL;
	pres->val.bool = (Var2Unsigned(ptp,pf) != 0);
	break;

      case V_IPADDR:
	pres->vartype = V_IPADDR;
	pres->val.pipaddr = Const2Ipaddr(pf);
	break;

      default:
	fprintf(stderr,"EvalConstant: unknown var type %d (%s)\n",
		pf->vartype, Vartype2Str(pf->vartype));
    }

}
    



static void
EvalFilter(
    tcp_pair *ptp,
    struct filter_res *pres,
    struct filter_node *pf)
{
    struct filter_res res;
    
    if (!pf) {
	fprintf(stderr,"EvalFilter called with NULL!!!\n");
	exit(-1);
    }

    /* variables are easy */
    if (pf->op == OP_VARIABLE) {
	EvalVariable(ptp,pres,pf);
	return;
    }

    /* constants are easy */
    if (pf->op == OP_CONSTANT) {
	EvalConstant(ptp,pres,pf);
	return;
    }

    switch (pf->op) {
      case OP_EQUAL:
      case OP_NEQUAL:
      case OP_GREATER:
      case OP_GREATER_EQ:
      case OP_LESS:
      case OP_LESS_EQ:
	if (pf->un.binary.left->vartype == V_ULLONG) {
	    EvalRelopUnsigned(ptp,&res,pf);
	    pres->vartype = V_BOOL;
	    pres->val.bool = res.val.bool;
	} else if (pf->un.binary.left->vartype == V_LLONG) {
	    EvalRelopSigned(ptp,&res,pf);
	    pres->vartype = V_BOOL;
	    pres->val.bool = res.val.bool;
	} else if (pf->un.binary.left->vartype == V_STRING) {
	    EvalRelopString(ptp,&res,pf);
	    pres->vartype = V_LLONG;
	    pres->val.longint = res.val.longint;
	} else if (pf->un.binary.left->vartype == V_IPADDR) {
	    EvalRelopIpaddr(ptp,&res,pf);
	    pres->vartype = V_BOOL;
	    pres->val.bool = res.val.bool;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pf->op, Op2Str(pf->op),
		    pf->vartype, Vartype2Str(pf->un.binary.left->vartype));
	    exit(-1);
	}
	break;

      case OP_PLUS:
      case OP_MINUS:
      case OP_TIMES:
      case OP_DIVIDE:
      case OP_MOD:
      case OP_BAND:
      case OP_BOR:
	if (pf->un.binary.left->vartype == V_ULLONG) {
	    EvalMathopUnsigned(ptp,&res,pf);
	    pres->vartype = V_ULLONG;
	    pres->val.u_longint = res.val.u_longint;
	} else if (pf->un.binary.left->vartype == V_LLONG) {
	    EvalMathopSigned(ptp,&res,pf);
	    pres->vartype = V_LLONG;
	    pres->val.longint = res.val.longint;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pf->op, Op2Str(pf->op),
		    pf->vartype, Vartype2Str(pf->un.binary.left->vartype));
	    exit(-1);
	}
	break;

      case OP_AND:
      case OP_OR:
	if (pf->vartype == V_BOOL) {
	    struct filter_res res1;
	    struct filter_res res2;
	    Bool ret;
	    if (pf->op == OP_OR) {
		EvalFilter(ptp,&res1,pf->un.binary.left);
		EvalFilter(ptp,&res2,pf->un.binary.right);
		ret = res1.val.bool || res2.val.bool;
	    } else {
		EvalFilter(ptp,&res1,pf->un.binary.left);
		EvalFilter(ptp,&res2,pf->un.binary.right);
		ret = res1.val.bool &&  res2.val.bool;
	    }
	    pres->vartype = V_BOOL;
	    pres->val.bool = ret;
	} else {
	    fprintf(stderr,
		    "EvalFilter: binary op %d (%s) not supported on data type %d (%s)\n",
		    pf->op, Op2Str(pf->op),
		    pf->vartype, Vartype2Str(pf->un.binary.left->vartype));
	    exit(-1);
	}
	break;

      case OP_NOT:
	if (pf->vartype == V_BOOL) {
	    EvalFilter(ptp,&res,pf->un.unary.pf);
	    pres->vartype = V_BOOL;
	    pres->val.bool = !res.val.bool;
	} else {
	    fprintf(stderr,
		    "EvalFilter: unary operation %d (%s) not supported on data type %d (%s)\n",
		    pf->op, Op2Str(pf->op),
		    pf->vartype, Vartype2Str(pf->vartype));
	    exit(-1);
	}
	break;

      default:
	fprintf(stderr,
		"EvalFilter: operation %d (%s) not supported on data type %d (%s)\n",
		pf->op,Op2Str(pf->op),
		pf->vartype,Vartype2Str(pf->vartype));
	exit(-1);
    }

    if (debug)
	printf("EvalFilter('%s') returns %s\n",
	       Filter2Str(pf),Res2Str(pres));

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
	       BOOL2STR(ret));

    return(ret);
}


static void
HelpFilterVariables(void)
{
    int i;

    fprintf(stderr,"Filter Variables:\n");

    fprintf(stderr,"  variable name      type      description\n");
    fprintf(stderr,"  -----------------  --------  -----------------------\n");

    for (i=0; i < NUM_FILTERS; ++i) {
	struct filter_line *pf = &filters[i];

	fprintf(stderr,"  %-17s  %-8s  %s\n",
		pf->varname, Vartype2BStr(pf->vartype),pf->descr);
    }
}



void
HelpFilter(void)
{
    HelpFilterVariables();

    fprintf(stderr,"\n\
Filter Syntax:\n\
  numbers:\n\
     variables:\n\
	anything from the above table with a prefix of either 'c_' meaning\n\
        the one for the Client or 's_' meaning the value for the Server.  If\n\
	the prefix is omitted, it means \"either one\" (effectively becoming\n\
	\"c_VAR OR s_VAR)\").  As shorthand for a conjunction instead, you can\n\
	use the syntax 'b_' (as in b_mss>100), meaning 'B'oth, (effectively\n\
	becoming \"c_VAR AND s_VAR)\").  For completeness, 'e_' means 'E'ither,\n\
	which is the normal default with no prefix.\n\
     constant:\n\
	strings:	anything in double quotes\n\
	booleans:	TRUE FALSE\n\
	numbers:	signed or unsigned constants\n\
  arithmetic operations: \n\
     any of the operators + - * / %% \n\
     performed on 'numbers'.  Normal operator precedence\n\
        is maintained (or use parens)\n\
  relational operators\n\
     any of < > = != >= <= applied to 'numbers'\n\
  boolean operators\n\
     AND, OR, NOT applied to the relational operators above\n\
  misc\n\
     use parens if you're not sure of the precedence\n\
     use parens anyway, you might be smarter than I am! :-)\n\
     you'll probably need to put the '-fexpr' expression in single quotes\n\
     matched connection numbers are saved in file %s for later processing\n\
	with '-o%s' (for graphing, for example).  This is helpful, because\n\
	all the work is done in one pass of the file, so if you graph while\n\
	using a filter, you'll get ALL graphs, not just the ones you want.\n\
        Just filter on a first pass, then use the \"-oPF\" flag with graphing\n\
	on the second pass\n\
     most common synonyms for NOT, AND, and OR also work (!,&&,||,-a,-o)\n\
	(for those of us with very poor memories\n\
Examples\n\
  tcptrace '-fsegs>10' file\n\
  tcptrace '-fc_segs>10 OR s_segs>20 ' file\n\
  tcptrace '-f c_segs+10 > s_segs ' file\n\
  tcptrace -f'thruput>10000 and segs > 100' file\n\
  tcptrace '-fb_segs>10' file\n\
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
filter_getc()
{
    static char *pinput = NULL;
    int ch;

    if (pinput == NULL)
	pinput = exprstr;

    if (*pinput == '\00') {
	static int doneyet = 0;
	if (++doneyet>1) {
	    if (debug > 4)
		printf("filter_getc() returns EOF\n");
	    return(EOF);
	} else {
	    if (debug > 4)
		printf("filter_getc() returns newline\n");
	    return('\n');
	}
    }

    ch = *pinput++;

    if (debug > 4)
	printf("filter_getc() returns char '%c'\n", ch);

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
    double tput_f;
    double etime;
    etime = elapsed(ptp->first_time,ptp->last_time);

    etime /= 1000000.0;  /* convert to seconds */

    if (etime == 0.0)
	return(0);

    tput_f = (double)(ptcb->unique_bytes) / etime;
    tput = (u_llong)(tput_f+0.5);

    if (debug)
	printf("VFuncTput(%s<->%s) = %llu\n",
	       ptcb->ptp->a_endpoint,
	       ptcb->ptp->b_endpoint,
	       tput);

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

