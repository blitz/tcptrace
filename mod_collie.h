/* header file for collie.c */
int collie_init(int argc, char *argv[]);
void collie_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmod_data);
void collie_done(void);
void collie_usage(void);
void *collie_newconn(tcp_pair *ptp);
