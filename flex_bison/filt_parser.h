typedef union	{ /* the types that we use in the tokens */
    char *string;
    long signed_long;
    u_long unsigned_long;
    ipaddr *pipaddr;
    Bool bool;
    enum optype op;
    struct filter_node *pf;
} YYSTYPE;
#define	EOS	257
#define	LPAREN	258
#define	RPAREN	259
#define	GREATER	260
#define	GREATER_EQ	261
#define	LESS	262
#define	LESS_EQ	263
#define	EQUAL	264
#define	NEQUAL	265
#define	NOT	266
#define	AND	267
#define	OR	268
#define	BAND	269
#define	BOR	270
#define	PLUS	271
#define	MINUS	272
#define	TIMES	273
#define	DIVIDE	274
#define	MOD	275
#define	VARIABLE	276
#define	STRING	277
#define	SIGNED	278
#define	UNSIGNED	279
#define	BOOL	280
#define	IPADDR	281


extern YYSTYPE filtyylval;
