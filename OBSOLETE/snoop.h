

#define SNOOP_DUMP_OFFSET 16



struct snoop_packet_header {
	unsigned int	tlen;
	unsigned int	len;
	unsigned int	unused2;
	unsigned int	unused3;
	unsigned int	secs;
	unsigned int	usecs;
};
