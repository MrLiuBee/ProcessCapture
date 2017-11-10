#define INIT_LINKLIST_LENGTH 200
#define LATER_INCRE_LENGTH 100

/*链表头结点信息结构体*/
struct LinkHead{
	struct PortScanner *Hps1;    /*tcp6*/
	struct PortScanner *Tps1;
	int ps1count;
	struct PortScanner *Hps2;    /*tcp*/
	struct PortScanner *Tps2;
	int ps2count;
	struct PortScanner *Hps3;    /*udp*/
	struct PortScanner *Tps3;
	int ps3count;
	struct PortScanner *Hps4;    /*udp6*/
	struct PortScanner *Tps4;
	int ps4count;
};

/*端口扫描及记录结构体*/
struct PortScanner{
	int DataItemNum;
	u_int time_usec_start;
	u_int time_usec_end;
	struct PortScanner *precur;
	struct PortScanner *nextcur;
	struct IP4PortMessage *portmsg1;
	struct IP6PortMessage *portmsg2;
};

/*IPv4端口信息结构体*/
struct IP4PortMessage{
	unsigned int local_addr;
	uint16_t local_port;
	unsigned int remote_addr;
	uint16_t remote_port;
	uint32_t cur_uid;
};

/*IPv6端口信息结构体*/
struct IP6PortMessage{
	unsigned int local_addr[4];
	uint16_t local_port;
	unsigned int remote_addr[4];
	uint16_t remote_port;
	uint32_t cur_uid;
};
