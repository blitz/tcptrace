/* header file for traffic.c */
int traffic_init(int argc, char *argv[]);
void traffic_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmod_data);
void traffic_done(void);
void traffic_usage(void);
void *traffic_newconn(tcp_pair *ptp);
