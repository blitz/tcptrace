/* header file for rttgraph.c */
int rttgraph_init(int argc, char *argv[]);
void rttgraph_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmod_data);
void rttgraph_done(void);
void rttgraph_usage(void);
void *rttgraph_newconn(tcp_pair *ptp);
