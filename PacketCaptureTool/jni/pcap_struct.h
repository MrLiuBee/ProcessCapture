#define PCAP_FILE_HDR_MAGIC 0xa1b2c3d4
#define PKT_HDR_LEN sizeof(struct pcap_pkthdr)
#define PKT_MAX_LEN 262144
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct pcap_file_header {
        u_int magic;
        u_short version_major;
        u_short version_minor;
        int thiszone;     /* gmt to local correction */
        u_int sigfigs;    /* accuracy of timestamps */
        u_int snaplen;    /* max length saved portion of each pkt */
        u_int linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
        //struct timeval ts;      /* time stamp */
	u_int time_sec;      /*this represents the number of whole seconds of elapsed time*/
	u_int time_usec;     /*this is the rest of the elapsed time, represent it as a number of microseconds*/
        u_int caplen;     /* length of portion present */
        u_int len;        /* length this packet (off wire) */
};

/*记录应用程序名称和UID的对应关系*/
struct app_msg {
	int uid;
	char appnm[50];
};

/*
 * TCP Header Structure
 * */
struct tcp_hdr {
  unsigned short tcp_src_port;
  unsigned short tcp_dest_port;
  unsigned int tcp_seq;
  unsigned int tcp_ack;
  unsigned char reserved:4;
  unsigned char tcp_offset:4;
  unsigned char tcp_flags;
  #define TCP_FIN   0x01
  #define TCP_SYN   0x02
  #define TCP_RST   0x04
  #define TCP_PUSH  0x08
  #define TCP_ACK   0x10
  #define TCP_URG   0x20
  unsigned short tcp_window;
  unsigned short tcp_checksum;
  unsigned short tcp_urgent;
};              
/*
 * Ethernet Header Structure
 * */
struct ether_hdr {
  unsigned char ether_dest_addr[ETHER_ADDR_LEN]; //MAC Destination Address
  unsigned char ether_src_addr[ETHER_ADDR_LEN];  //MAC Source Address
  unsigned short ether_type; //Type
};
/*
 * IP Header Structure
 * */
struct ip_hdr {
  unsigned char ip_version_and_header_length;
  unsigned char ip_tos;
  unsigned short ip_len;
  unsigned short ip_id;
  unsigned short ip_frag_offset;
  unsigned char ip_ttl;
  unsigned char ip_type;
  unsigned short ip_checksum;
  unsigned int ip_src_addr;
  unsigned int ip_dest_addr;
};
