/* opaque handle */
typedef struct dyn_counter *dyn_counter;


/* access routines */
void DestroyCounters(dyn_counter *phandle);
void AddToCounter(dyn_counter *phandle, unsigned long ix, unsigned long val);
void SetCounter(dyn_counter *phandle, unsigned long ix, unsigned long val);
unsigned long MaxCounter(dyn_counter handle);
unsigned long MinCounter(dyn_counter handle);
unsigned long TotalCounter(dyn_counter handle);
unsigned long LookupCounter(dyn_counter handle, unsigned long ix);
int NextCounter(dyn_counter *phandle, void *pcookie,
		unsigned long *pix, unsigned long *pcount);

