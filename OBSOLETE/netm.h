

#define NETM_DUMP_OFFSET 0x1000



/* netm file header format */
struct netm_header {
	int	netm_key;
	int	version;
};
#define VERSION_OLD 3
#define VERSION_NEW 4
#define NETM_KEY 0x6476


/* netm packet header format */
struct packet_header_old {
	int	unused1;
	int	unused2;
	int	tstamp_secs;
	int	tstamp_usecs;
	int	unused3;
	int	len;
};
struct packet_header {
	int	unused1;
	int	tstamp_secs;
	int	tstamp_usecs;
	int	unused2;
	int	unused3;
	int	len;
	int	tlen;  /* truncated length */
	int	unused5;
};
