

#define SNOOP_DUMP_OFFSET 16



struct snoop_packet_header {
	unsigned int	tlen;
	unsigned int	len;
	unsigned int	junk2;
	unsigned int	junk3;
	unsigned int	secs;
	unsigned int	usecs;
};
