/* header file for http.c */
int http_init(int argc, char *argv[]);
void http_read(struct ip *pip, tcp_pair *ptp, void *plast);
void http_done(void);
void http_usage(void);
