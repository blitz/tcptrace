/* header file for http.c */
int http_init(int argc, char *argv[]);
void http_read(struct ip *pip, tcp_pair *ptp, void *plast, void *pmod_data);
void http_done(void);
void http_usage(void);
void http_newfile(char *newfile);
void *http_newconn(tcp_pair *ptp);
