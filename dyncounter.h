/* opaque handle */
typedef struct dyn_counter *dyn_counter;


/* adding/setting counters */
void AddToCounter(dyn_counter *phandle, unsigned long ix,
		  unsigned long val, unsigned long granularity);
void SetCounter(dyn_counter *phandle, unsigned long ix,
		unsigned long val, unsigned long granularity);


/* lookup various counter values */
unsigned long GetMaxIx(dyn_counter handle);
unsigned long GetMinIx(dyn_counter handle);
unsigned long GetMaxCount(dyn_counter handle);
unsigned long GetTotalCounter(dyn_counter handle);
unsigned long GetGran(dyn_counter handle);

/* query counter values */
unsigned long LookupCounter(dyn_counter handle, unsigned long ix);
int NextCounter(dyn_counter *phandle, void *pcookie,
		unsigned long *pix, unsigned long *pcount);

/* when you're finished */
void DestroyCounters(dyn_counter *phandle);
