/* a simple, dynamic string library */

typedef struct dstring dstring_t;


/* dstring access routines */
dstring_t *DSNew(void);
void DSDestroy(dstring_t **ppds);
void DSErase(dstring_t *pds);
void DSAppendChar(dstring_t *pds, char ch);
void DSAppendString(dstring_t *pds, char *str);
void DSAppendStringN(dstring_t *pds, char *str, int len);
char *DSVal(dstring_t *pds);


