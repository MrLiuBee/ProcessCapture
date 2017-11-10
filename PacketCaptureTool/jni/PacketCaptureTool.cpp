#include <jni.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
//#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <android/log.h>

#include "pcap_struct.h"
#include "port_map.h"

#define KEY_ESC 27
#define MAX_INTERFACE_NUM 16
#define MAX_INTEGER_LEN 10

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define FILE_NAME_LEN 256
#define CAP_FILE_DIR "packet_capture"
#define STATS_FILE ".cap_stats"
#define PCAP_FILE_SUFFIX "pcap"

#define BUFF_BKT_CNT_MAX 100
#define BUFF_SIZE ((BUFF_BKT_CNT_MAX)*(PKT_HDR_LEN+PKT_MAX_LEN))

/*
 * 解析系统流量文件变量定义声明
 */
#define _PATH_PROCNET_TCP "/proc/net/tcp"
#define _PATH_PROCNET_TCP6 "/proc/net/tcp6"
#define _PATH_PROCNET_UDP "/proc/net/udp"
#define _PATH_PROCNET_UDP6 "/proc/net/udp6"

struct LinkHead LH;
FILE* procinfo;
struct timeval ts, tv;
pthread_t thread_id1, thread_id2, thread_id3, thread_id4;
int count1 = 0;
int count2 = 0;
int count3 = 0;
int count4 = 0;

/*
 * 抓包变量声明定义
 */
//struct timeval ts;
int capture = 1;
char file_name[FILE_NAME_LEN] = {0};
char stats_file_dir[FILE_NAME_LEN-sizeof(STATS_FILE)] = {0};

struct pcap_pkthdr* ppkthdr = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
char* buffer;
char* ppkt_start;
FILE* file;

time_t time_now;
int capture_count = 0;
int total_capture_count = 0;
int need_write_len;
int write_len;
int recv_len;
int sock_fd;

pthread_t thread_id;

const struct ip_hdr *ip_header;
const struct tcp_hdr *tcp_header;
unsigned int ip_src_addr, ip_dest_addr;
unsigned short tcp_src_port, tcp_dest_port;

struct app_msg *AppMsg = (struct app_msg*)malloc(300 * sizeof(struct app_msg));
int app_msg_len = 0;
char fname[50] = {0};
char fname1[50] = "i_record";
char savedir[50] = {0};
char savedir1[50] = "/storage/emulated/0/i_record";
struct pcap_file_header file_header;

#ifdef __cplusplus
extern "C" {
#endif

void init_file_header(struct pcap_file_header* pfile_hdr, int cap_len)
{
	pfile_hdr->magic = PCAP_FILE_HDR_MAGIC;
	pfile_hdr->version_major = PCAP_VERSION_MAJOR;
	pfile_hdr->version_minor = PCAP_VERSION_MINOR;
	pfile_hdr->thiszone = 0;
	pfile_hdr->sigfigs = 0;
	pfile_hdr->snaplen = cap_len;
	pfile_hdr->linktype = 1; /* ethernet */
}

/*
 * 向stats_file中写入stats
 */
int write_statistics(char* stats_file, int stats)
{
	int writelen;
	char intArr[MAX_INTEGER_LEN] = {0};

	if(NULL == stats_file)
	{
		return -1;
	}

	FILE* file = fopen(stats_file, "wb");
	if(NULL == file)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "open statistics file %s failed, %s", stats_file, strerror(errno));
		return errno;
	}

	sprintf(intArr, "%d", stats);
	writelen = fwrite(intArr, sizeof(char), MAX_INTEGER_LEN, file);
	if(writelen <= 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind","write statistics fail, %s", strerror(errno));
		return errno;
	}

	fclose(file);
	return 0;
}

/*
 * 抓包线程
 */
void* capture_thread(void* arg)
{
	//printf("dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf!\n");
	//printf("%d\n",sizeof(struct pcap_pkthdr));
	/*获取每次抓包时的开始时间*/
	time(&time_now);
	struct tm* now = localtime(&time_now);
	now->tm_year += 1900;

	while(capture)
	{
		usleep(10000);
		//printf("wakeup the capture!\n");
		//recv_len = recv(sock_fd, ppkt_start, PKT_MAX_LEN, MSG_DONTWAIT);
		recv_len = recvfrom(sock_fd, buffer, PKT_MAX_LEN, 0, NULL, NULL);
		FILE *p1;
		int fexist;
		if(recv_len < 46)
		{
			/*if(errno != EAGAIN)
			{
				__android_log_print(ANDROID_LOG_INFO, "sprintwind", "recv failed, %s", strerror(errno));
				return NULL;
			}*/
			//printf("Incomplete header, packet corrupt\n");
			continue;
		}
		//usleep(10000);

		/*获取一条数据帧的源ip地址，目的ip地址，源端口和目的端口
		ip_header = (const struct ip_hdr*)(buffer+14);
		ip_src_addr = ip_header->ip_src_addr;
		ip_dest_addr = ip_header->ip_dest_addr;

		tcp_header = (const struct tcp_hdr*)(buffer+14+sizeof(struct ip_hdr));
		tcp_src_port = ntohs(tcp_header->tcp_src_port);
		tcp_dest_port = ntohs(tcp_header->tcp_dest_port);

		//printf("at the start,ip_src_addr: %X, ip_dest_addr: %X, tcp_src_port: %X, tcp_dest_port: %X\n",ip_src_addr,ip_dest_addr,tcp_src_port,tcp_dest_port);

		查找tcp6,tcp,udp,udp6快照记录
		unsigned int rd_lo_ip_addr;
		unsigned short rd_lo_port;
		int uid = -1;
		int i, j, fexist;
		struct PortScanner *pscur;
		struct IP6PortMessage *IP6cur;
		struct IP4PortMessage *IP4cur;
		FILE *p1;
		while(1){
		//tcp6文件
	    pscur = LH.Tps1;
	    if(pscur == NULL)
	    {//printf("at the tcp6 start,pscur is null\n");
	    break;}
	    IP6cur = pscur->portmsg2;
	    if(IP6cur == NULL)
	    {//printf("at the tcp6 start,IP6cur is null\n");
	    break;}
		rd_lo_ip_addr = IP6cur->local_addr[3];
		rd_lo_port = IP6cur->local_port;
		j = 0;

		//printf("ps1count=:%d\n",LH.ps1count);
		while(pscur!=NULL && j < 5){
			//printf("enter while1\n");
			i = 0;
			while(i < pscur->DataItemNum){
//				printf("enter while2,tcp6 dataitemnum=:%d\n",pscur->DataItemNum);
//				printf("ip_src_addr:%X, rd_lo_ip_addr:%X\n", ip_src_addr, rd_lo_ip_addr);
//				printf("record local ip port uid,lo_ip:%X,lo_port:%X,uid:%d\n",rd_lo_ip_addr,rd_lo_port,IP6cur->cur_uid);
				if(ip_src_addr == rd_lo_ip_addr){
					if(tcp_src_port == rd_lo_port)
						{uid = IP6cur->cur_uid;break;}
				}//if
				else{
					if(tcp_dest_port == rd_lo_port)
						{uid = IP6cur->cur_uid;break;}
				}//else
				IP6cur++;
				if(IP6cur == NULL){
					//printf("tcp6 IP6cur is null!\n");
					break;
				}
				i++;
				//printf("i = :%d\n",i);
				rd_lo_ip_addr = IP6cur->local_addr[3];
				rd_lo_port = IP6cur->local_port;
			}//第一层while

			//printf("quit the while2\n");
			//printf("the uid = %d\n",uid);
			if(uid != -1)
				break;
			pscur = pscur->precur;
			if(pscur == NULL)
				{//printf("tcp6 pscur is null!\n");
				break;}
		    IP6cur = pscur->portmsg2;
		    if(IP6cur == NULL)
		    	{//printf("out tcp6 IP6cur is null!\n");
		    	break;}
		    rd_lo_ip_addr = IP6cur->local_addr[3];
		    //printf("pipipipipipi\n");
		    rd_lo_port = IP6cur->local_port;

		    j++;
		}//第二层while

		//printf("after lookup the tcp6!%d\n", uid);
		if(uid != -1)
			break;

		//tcp文件
		pscur = LH.Tps2;
		if(pscur == NULL)
	    {//printf("at the tcp start,pscur is null\n");
	    break;}
		IP4cur = pscur->portmsg1;
		if(IP4cur == NULL)
		{//printf("at the tcp start,IP4cur is null\n");
		break;}
		rd_lo_ip_addr = IP4cur->local_addr;
		rd_lo_port = IP4cur->local_port;
		j = 0;
		while(pscur!=NULL && j <5){
			i = 0;
			while(i < pscur->DataItemNum){
				//printf("enter tcp while1\n");
				if(ip_src_addr == rd_lo_ip_addr){
					if(tcp_src_port == rd_lo_port)
						{uid = IP4cur->cur_uid;break;}
				}//if
				else{
					if(tcp_dest_port == rd_lo_port)
						{uid = IP4cur->cur_uid;break;}
				}//else
				IP4cur++;
				i++;
				if(IP4cur == NULL){
					//printf("tcp IP4cur is null!\n");
					break;
				}
				rd_lo_ip_addr = IP4cur->local_addr;
				rd_lo_port = IP4cur->local_port;
			}//第一层while

			//printf("quit tcp while1\n");
			if(uid != -1)
				break;
			pscur = pscur->precur;
			if(pscur == NULL)
			{//printf("tcp pscur is null!\n");
			break;}
			IP4cur = pscur->portmsg1;
			if(IP4cur == NULL)
			{//printf("out tcp IP4cur is null\n");
			break;}
			rd_lo_ip_addr = IP4cur->local_addr;
			rd_lo_port = IP4cur->local_port;

			j++;
		}//第二层while

		//printf("quit the tcp scan!%d\n", uid);
		if(uid != -1)
			break;

		//udp文件
		pscur = LH.Tps3;
		if(pscur == NULL)
		{//printf("at the udp start,pscur is null\n");
		break;}
		IP4cur = pscur->portmsg1;
		if(IP4cur == NULL)
		{//printf("at the udp start,IP4cur is null\n");
		break;}
		rd_lo_ip_addr = IP4cur->local_addr;
		rd_lo_port = IP4cur->local_port;
		j = 0;
		while(pscur!=NULL && j < 5){
			//printf("ps3count=:%d\n",LH.ps3count);
			i = 0;
			while(i < pscur->DataItemNum){
				//printf("enter udp while1\n");
				if(ip_src_addr == rd_lo_ip_addr){
					if(tcp_src_port == rd_lo_port)
						{uid = IP4cur->cur_uid;break;}
				}//if
				else{
					if(tcp_dest_port == rd_lo_port)
						{uid = IP4cur->cur_uid;break;}
				}//else
				IP4cur++;
				i++;
				if(IP4cur == NULL)
				{//printf("udp IP4cur is null!\n");
				break;}
				rd_lo_ip_addr = IP4cur->local_addr;
				rd_lo_port = IP4cur->local_port;
			}//第一层while
			//printf("quit udp while1\n");

			//printf("udp j=:%d\n",j);
			if(uid != -1)
				break;

			pscur = pscur->precur;
			if(pscur == NULL)
			{//printf("udp pscur is null!\n");
			break;}
			IP4cur = pscur->portmsg1;
			if(IP4cur == NULL)
			{//printf("out udp IP4cur is null!\n");
			break;}
			rd_lo_ip_addr = IP4cur->local_addr;
			rd_lo_port = IP4cur->local_port;

			j++;
		}//第二层while

		//printf("quit the udp scan!%d\n",uid);
		if(uid != -1)
			break;

		//udp6文件
		pscur = LH.Tps4;
		if(pscur == NULL)
		{//printf("at the udp6 start,pscur is null\n");
		break;}
		IP6cur = pscur->portmsg2;
		if(IP6cur == NULL)
		{//printf("at the udp6 start,IP6cur is null\n");
		break;}
		rd_lo_ip_addr = IP6cur->local_addr[3];
		rd_lo_port = IP6cur->local_port;
		j = 0;
		while(pscur!=NULL && j < 5){
			i = 0;
			while(i < pscur->DataItemNum){
				if(ip_src_addr == rd_lo_ip_addr){
					if(tcp_src_port == rd_lo_port)
						{uid = IP6cur->cur_uid;break;}
				}//if
				else{
					if(tcp_dest_port == rd_lo_port)
						{uid = IP6cur->cur_uid;break;}
				}//else
				IP6cur++;
				i++;
				if(IP6cur == NULL)
				{//printf("udp6 IP6cur is null!\n");
				break;}
				rd_lo_ip_addr = IP6cur->local_addr[3];
				rd_lo_port = IP6cur->local_port;
			}//第一层while

			if(uid != -1)
				break;
			pscur = pscur->precur;
			if(pscur == NULL)
			{//printf("udp6 pscur is null!\n");
			break;}
			IP6cur = pscur->portmsg2;
			if(IP6cur == NULL)
			{//printf("out udp6 IP6cur is null!\n");
			break;}
			rd_lo_ip_addr = IP6cur->local_addr[3];
			rd_lo_port = IP6cur->local_port;

			j++;
		}//第二层while

		//printf("quit the udp6 scan!%d\n",uid);
		break;}

		//printf("enter getname by uid!\n");


		if(uid != -1){
			//printf("app_msg_len:%d\n",app_msg_len);
			for(i = 0; i < app_msg_len ; i++)
			{
				if((AppMsg+i) == NULL)
				{//printf("have ended,AppMsg+i is null!\n");
				break;}
				//printf("AppMsg[%d] uid: %d,appname: %s\n",i,(AppMsg+i)->uid,(AppMsg+i)->appnm);
				if((AppMsg+i)->uid == uid)
				{
					memcpy(fname, (AppMsg+i)->appnm, 22);
					//strcpy(fname, (AppMsg+i)->appnm);
					sprintf(file_name, "%s/%s%02d%02d%02d%02d.%s", savedir, fname, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec, PCAP_FILE_SUFFIX);
					break;
				}//if
			}
		}
		else{
			strcpy(fname1, "else");
			sprintf(file_name, "%s/%s.%s", savedir1, fname1, PCAP_FILE_SUFFIX);
		}

		针对获取的UID，找不到对应的应用名称
		if(fname[0] == 0){
			//printf("Can't find the filename for UID!\n");
			//return errno;如何进行程序错误控制
			strcpy(fname1, "else");
			sprintf(file_name, "%s/%s.%s", savedir1, fname1, PCAP_FILE_SUFFIX);
		}
		//printf("file_name=:%s\n",fname);
		若文件不存在，则记录为0，否则记录为1*/
		if((p1 = fopen(file_name, "rb")) == NULL)
			fexist = 0;
		else
			fexist = 1;
		if(p1 != NULL)
			fclose(p1);

		//printf("fexist=:%d\n",fexist);
		//创建对应的pcap文件
		file = fopen(file_name, "ab+");
		if(NULL == file)
		{
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fopen:%s", file_name);
			//return errno;
			break;
		}
		if(fexist == 0){
			//写入文件头
			need_write_len = sizeof(struct pcap_file_header);
			if( fwrite(&file_header, sizeof(char), need_write_len, file) < need_write_len)
			{
				__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fwrite");
				//return errno;
				break;
			}
		}

        //printf("have write the file header\n");




		//gettimeofday(&ppkthdr->ts, NULL);
		gettimeofday(&ts,NULL);
		ppkthdr->time_usec = ts.tv_usec;
		ppkthdr->time_sec = ts.tv_sec;
		ppkthdr->caplen = recv_len;
		ppkthdr->len = recv_len;
        if(fwrite(ppkthdr, sizeof(struct pcap_pkthdr), 1, file) < 1)
        {
        	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fwrite failed");
        	return NULL;
        }
        /*char inet[14]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x86,0xDD};
        fwrite(inet, 14, 1, file);*/

        fflush(file);
		//__android_log_print(ANDROID_LOG_INFO, "sprintwind", "recv a packet, packet len:%d\n", recv_len);
		//printf("recv a packet, pcaket len:%d\n", recv_len);

		//capture_count++;
		total_capture_count++;
		//need_write_len += (recv_len+PKT_HDR_LEN);
		//printf("captured %d\n", total_capture_count);
		//MOVE_UP(2);

		if(fwrite(buffer, recv_len, 1, file) < 1)
		{
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fwrite failed");
			return NULL;
		}
		fflush(file);
		memset(buffer, 0, PKT_MAX_LEN);
		fclose(file);
	}
    
    //printf("dsjdkjfkdjfgjkdkf\n");


	fclose(file);
    //printf("capture file stop, close the file!\n");
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "capture stopped, %d packets captured, saved to file %s\n", total_capture_count, file_name);

	char stats_file[FILE_NAME_LEN] = {0};

	sprintf(stats_file, "%s/%s", stats_file_dir, STATS_FILE);

	/* 每次结束时，将抓包统计值清零 */
	write_statistics(stats_file, 0);

	/* 释放资源 */
	close(sock_fd);
	free(buffer);
	fclose(file);

	return NULL;
}


/*
 * 打印抓包状态线程
 */
void* print_thread(void* arg)
{
	//printf("enter print_thread!\n");
	char stats_file[FILE_NAME_LEN] = {0};

	sprintf(stats_file, "%s/%s", stats_file_dir, STATS_FILE);

	while(capture)
	{
		/* 将抓包个数写入统计文件 */
		if(0 != write_statistics(stats_file, total_capture_count))
		{
			break;
		}

		sleep(1);
	}

	write_statistics(stats_file, 0);

	return NULL;
}

int start_capture(char* dev, int proto, int cap_len, char* saveFileName)
{
	struct sock_fprog fprog;
	struct ifreq interface;
	struct sock_filter filter[] = {
					{ 0x28, 0, 0, 0x0000000c },
					{ 0x15, 0, 3, 0x00000800 },
					{ 0x30, 0, 0, 0x00000017 },
					{ 0x15, 0, 1, proto },
					{ 0x6, 0, 0, cap_len },
					{ 0x6, 0, 0, 0x00000000 }
				    };

	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(proto));
	if(sock_fd < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "socket failed");
		return errno;
	}
    //printf("liuliuliuiuuliuuliuliuliuliuliuliuliuliuliul8iuiliuiiuiulluilliuilliuililiiuliuliuliuiliuliuliuliuiiuuliuo\n");
	/* 输入了设备则进行绑定 */
	if((NULL != dev)&&(0 != memcmp("all", dev, 3)))
	{
		strncpy(interface.ifr_ifrn.ifrn_name, dev, IFNAMSIZ);

		if( setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0)
		{
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "SO_BINDTODEVICE failed");
			return errno;
		}
	}

	/*设置过滤条件
	fprog.filter = filter;
	fprog.len = sizeof(filter)/sizeof(struct sock_filter);
	if( setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "SO_ATTACH_FILTER");
		return errno;
	}*/


	/* 初始化pcap文件头 */
	init_file_header(&file_header, cap_len);

	// 生成文件名
	time(&time_now);
	struct tm* now = localtime(&time_now);
	now->tm_year += 1900;

	sprintf(file_name, "%s/%04d%02d%02d%02d%02d%02d.%s", savedir, now->tm_year, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec, PCAP_FILE_SUFFIX);


	/*sprintf(file_name, "%s/%s.%s", saveDir, saveFileName, PCAP_FILE_SUFFIX);

	 创建pcap文件
	file = fopen(file_name, "wb+");
	if(NULL == file)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fopen:%s", file_name);
		return errno;
	}

	 写入文件头
	need_write_len = sizeof(struct pcap_file_header);
	if( fwrite(&file_header, sizeof(char), need_write_len, file) < need_write_len)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fwrite");
		return errno;
	}

	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "write file header %d bytes\n", need_write_len);*/

	/* 偏移写文件位置到文件头后面 */
	//fseek(file, need_write_len, SEEK_SET);

	/* 分配报文缓冲区 */
	buffer = (char*)malloc(PKT_MAX_LEN);
	if(NULL == buffer)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "alloc memory for buffer failed\n");
		return -1;
	}

	memset(buffer, 0, PKT_MAX_LEN);

	//ppkthdr = (struct pcap_pkthdr*)buffer;
	//ppkt_start = (char*)ppkthdr + PKT_HDR_LEN;

	//capture_count = 0;
	total_capture_count = 0;
	need_write_len = 0;

	/*
	if(0 != pthread_create(&thread_id, NULL, capture_thread, NULL) )
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "create capture thread failed\n");
		return -1;
	}
	*/

	char stats_file[FILE_NAME_LEN] = {0};

	sprintf(stats_file, "%s/%s", stats_file_dir, STATS_FILE);

	/* 每次开始时，将抓包统计值清零 */
	write_statistics(stats_file, 0);


	if(0 != pthread_create(&thread_id, NULL, print_thread, NULL))
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "create print thread failed\n");
		return -1;
	}


	capture_thread(NULL);

	return 0;

}

void stop_capture(int sig)
{
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "recv a signal, goto stop capture");
	capture = 0;
	//printf("enter stop capture!\n");
}

int get_protocol_value(char* proto)
{
	if(NULL == proto)
	{
		return -1;
	}

	if(0==strcmp(proto, "ARP"))
	{
		return ETH_P_ARP;
	}

	if(0==strcmp(proto, "IP"))
	{
		return ETH_P_IP;
	}

	if(0==strcmp(proto, "ALL"))
	{
		return ETH_P_ALL;
	}

	return -1;
}




/*
 * 解析系统文件/proc/net/tcp,tcp6,udp,udp6,获取应用UID和流量端口的对应关系。
 */
/*
 * 从链表中删除节点
 */
static int DeleteEleLinkList(struct PortScanner *p){
	//printf("enter delete!\n");
	p->precur->nextcur = p->nextcur;
	p->nextcur->precur = p->precur;
	free(p);
	return 1;
}

/*
 * 删除快照链表中持续时间大于1minute的记录
 */
static void* RefreshSnap(void* arg){
	struct PortScanner *ps1, *ps2, *ps3, *ps4, *ps;
	u_int curtime;
    //printf("go to refresh snap!\n");
while(capture)
{
	//printf("testtesttest!\n");
	/*每10s扫描一次*/
	usleep(10000000);
	//printf("mumumummuuumuu!\n");
	//printf("orign: %d %d %d %d\n", LH.ps1count, LH.ps2count, LH.ps3count, LH.ps4count);
	/*获取当前系统时间*/
	gettimeofday(&tv, NULL);
	curtime = tv.tv_usec / 1000 + tv.tv_sec * 1000;

	/*删除tcp6快照记录中保存时间大于10s的节点*/
	ps1 = ps = LH.Hps1;
	while(ps1){
		//printf("judge the time record!\n");
		if(curtime-ps1->time_usec_start > 10000)
		{
			//printf("enterif!\n");
			ps1 = ps->nextcur;

			LH.Hps1 = ps1;
			free(ps);

			ps = ps1;
			LH.ps1count--;
		}//if
		else
		{//printf("enterelse!\n");
		break;  }

		//printf("judge the!\n");
	}//while
	//printf("judge!\n");
	/*删除tcp快照记录中大于1minute的节点*/
	ps2 = ps = LH.Hps2;
	while(ps2){
		if(curtime-ps2->time_usec_start > 10000)
		{
			ps2 = ps->nextcur;

			LH.Hps2 = ps2;
			free(ps);

			ps = ps2;
			LH.ps2count--;
		}//if
		else
			break;
	}//while

	/*删除udp快照记录中大于1minute的节点*/
	ps3 = ps = LH.Hps3;
	while(ps3){
		if(curtime-ps3->time_usec_start > 10000)
		{
			ps3 = ps->nextcur;

			LH.Hps3 = ps3;
			free(ps);

			ps = ps3;
			LH.ps3count--;
		}//if
		else
			break;
	}//while

	/*删除udp6中快照记录中大于1minute的节点*/
	ps4 = ps = LH.Hps4;
	while(ps4){
		if(curtime-ps4->time_usec_start > 10000)
		{
			ps4 = ps->nextcur;

			LH.Hps4 = ps4;
			free(ps);

			ps = ps4;
			LH.ps4count--;
		}//if
		else
			break;
	}//while

	//printf("newst: %d %d %d %d\n", LH.ps1count, LH.ps2count, LH.ps3count, LH.ps4count);
}//while(1)

	return NULL;
}

/*
 * tcp数据存储函数，将缓冲区中的内容写入到存储结构中
 */
static void tcp_do_one(char *buffer,char *ftype, struct PortScanner *pscan, int incrlen){
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128];
	struct IP6PortMessage *pt2;
	struct IP4PortMessage *pt1;

	//printf("tcptcptcptcptcptcptpctcpptpcptcpptcptcptcpptpcpgpcptpcfpcptcp!\n");
	num = sscanf(buffer,
	"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
	     &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	     &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

	if(num < 11){
		fprintf(stderr, ("warning, got bogus tcp line.\n"));
		return;
	}
	//printf("incrlen = :%d\n", incrlen);
	if(strlen(local_addr) > 8){
		//printf("ipv6 address:%s\n", local_addr);
		//printf("ipv6 port:%X\n", local_port);
//#if HAVE_AFINET6
	/*纠正内核给我们的信息内容*/
	pt2 = pscan->portmsg2 + incrlen;
	sscanf(local_addr, "%08X%08X%08X%08X",
			&(pt2->local_addr[0]), &(pt2->local_addr[1]),
			&(pt2->local_addr[2]), &(pt2->local_addr[3]));
	pt2->local_port = local_port;

	sscanf(rem_addr, "%08X%08X%08X%08X",
			&(pt2->remote_addr[0]), &(pt2->remote_addr[1]),
			&(pt2->remote_addr[2]), &(pt2->remote_addr[3]));
	pt2->remote_port = rem_port;
	pt2->cur_uid = uid;
	//printf("IPV6, local adddress:%X, local port:%X, UID:%d\n", pt2->local_addr[3], pt2->local_port, pt2->cur_uid);
//#endif
	}
	else{
		//printf("ipv4 address:%s\n", local_addr);
		//printf("ipv4 port:%X\n", local_port);
		pt1 = pscan->portmsg1 +incrlen;
		sscanf(local_addr, "%X", &pt1->local_addr);
		sscanf(rem_addr, "%X", &pt1->remote_addr);
		pt1->local_port = local_port;
		pt1->remote_port = rem_port;
		pt1->cur_uid = uid;
		//printf("IPV4, local adddress:%X, local port:%X, UID:%d\n", pt1->local_addr, pt1->local_port, pt1->cur_uid);
	}

}

/*
 * 读取系统文件（tcp,tcp6,udp,udp6），文件内容暂存到buffer缓冲区中
 * 并最后将缓冲区内容写入到建立的存储结构中
 */
static int INFO_GUTS(char *file1,char *filetype){
	int tag = -1;
	int incrlen = 0;
	int totallen = INIT_LINKLIST_LENGTH;
	char buffer[8192];
	struct IP6PortMessage *top6 = (struct IP6PortMessage*)malloc(sizeof(struct IP6PortMessage));
	struct IP4PortMessage *top4 = (struct IP4PortMessage*)malloc(sizeof(struct IP4PortMessage));

	/*建立快照存储结构头结点*/
	struct PortScanner *pscan = (struct PortScanner*)malloc(sizeof(struct PortScanner));
	//printf("enter and record file message!\n");
	if(filetype == "tcp6")
	{
		//printf("read file tcp6!\n");
		if(LH.ps1count == 0)
		{
			LH.Hps1 = LH.Tps1 = pscan;
			pscan->precur = NULL;
			pscan->nextcur = NULL;
		}
		else
		{
			pscan->precur = LH.Tps1;
			pscan->nextcur = NULL;
			LH.Tps1->nextcur = pscan;
			LH.Tps1 = pscan;
		}
		//printf("tcp6!\n");

	}
	else if(filetype == "tcp")
	{
		//printf("read file tcp!\n");
		if(LH.ps2count == 0)
		{
			LH.Hps2 = LH.Tps2 = pscan;
			pscan->precur = NULL;
			pscan->nextcur = NULL;
		}
		else
		{
			pscan->precur = LH.Tps2;
			pscan->nextcur = NULL;
			LH.Tps2->nextcur = pscan;
			LH.Tps2 = pscan;
		}
	}
	else if(filetype == "udp")
	{
		//printf("read file udp!\n");
		if(LH.ps3count == 0)
		{
			LH.Hps3 = LH.Tps3 = pscan;
			pscan->precur = NULL;
			pscan->nextcur = NULL;
		}
		else
		{
			pscan->precur = LH.Tps3;
			pscan->nextcur = NULL;
			LH.Tps3->nextcur = pscan;
			LH.Tps3 = pscan;
		}
	}
	else if(filetype == "udp6")
	{
		//printf("read file udp6!\n");
		if(LH.ps4count == 0)
		{
			LH.Hps4 = LH.Tps4 =pscan;
			pscan->precur = NULL;
			pscan->nextcur = NULL;
		}
		else
		{
			pscan->precur = LH.Tps4;
			pscan->nextcur = NULL;
			LH.Tps4->nextcur = pscan;
			LH.Tps4 = pscan;
		}
	}
    //printf("initial the record file!\n");
	/*为端口信息结构体分配空间*/
	if(filetype == "tcp6" || filetype == "udp6")
	{
		tag = 1;
		pscan->portmsg2 = (struct IP6PortMessage*)malloc(INIT_LINKLIST_LENGTH*sizeof(struct IP6PortMessage));
		top6 = pscan->portmsg2;
		//record = PM;
	}
	else if(filetype == "tcp" || filetype == "udp")
	{
		tag = 0;
		pscan->portmsg1 = (struct IP4PortMessage*)malloc(INIT_LINKLIST_LENGTH*sizeof(struct IP4PortMessage));
		top4 = pscan->portmsg1;
		//record = PM;
	}

	procinfo = fopen(file1, "r");
	if(procinfo == NULL){
		return -1;
	}

	/*写入快照结点开始时间*/
	gettimeofday(&ts,NULL);
	pscan->time_usec_start = ts.tv_usec / 1000 + ts.tv_sec * 1000;

	if(fgets(buffer, sizeof(buffer), procinfo))
	/*eat line*/;

	/*循环读取并处理系统文件*/
	do{
		//printf("wowowowowowowowowowowowowowowowowowowowowowowowowwowow\n");
		if(tag == 1)
		{
			if(top6-pscan->portmsg2 >= totallen){
				printf("realloc ipv6!\n");
				pscan->portmsg2 = (struct IP6PortMessage*)realloc(pscan->portmsg2, (totallen+LATER_INCRE_LENGTH)*sizeof(struct IP6PortMessage));
				top6 = pscan->portmsg2 + totallen;
				totallen += LATER_INCRE_LENGTH;
			}
		}
		else if(tag == 0)
		{
			if(top4-pscan->portmsg1 >= totallen){
				printf("realloc ipv4!\n");
				pscan->portmsg1 = (struct IP4PortMessage*)realloc(pscan->portmsg1, (totallen+LATER_INCRE_LENGTH)*sizeof(struct IP4PortMessage));
			    top4 = pscan->portmsg1 + totallen;
			    totallen += LATER_INCRE_LENGTH;
			}
		}
		if(!top4 || !top6)
		{
			printf("realloc failed!");
			return -1;
		}

		if(fgets(buffer, sizeof(buffer), procinfo))
		{
			//printf("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm\n");
			tcp_do_one(buffer, filetype, pscan, incrlen);
			incrlen++;
		}
		//printf("scan lines: %d\n",incrlen);
	}while(!feof(procinfo));
    pscan->DataItemNum = incrlen;
    //printf("early DataItemNum = :%d\n", pscan->DataItemNum);
    incrlen = 0;
	/*写入快照节点结束时间
	gettimeofday(&ts,NULL);
	pscan->time_usec_end = ts.tv_usec;*/
	fclose(procinfo);

	/*快照个数加1*/
	if(filetype == "tcp6")
		LH.ps1count++;
	else if(filetype == "tcp")
		LH.ps2count++;
	else if(filetype == "udp")
		LH.ps3count++;
	else if(filetype == "udp6")
		LH.ps4count++;

	return 0;
}

/*
 * 持续解析系统文件处理函数
 */
static void analysis(){
	while(capture)
	{
		int i = 0;
		//printf("enter into analysis!\n");
		INFO_GUTS(_PATH_PROCNET_TCP6, "tcp6");
		INFO_GUTS(_PATH_PROCNET_TCP, "tcp");
		INFO_GUTS(_PATH_PROCNET_UDP, "udp");
		INFO_GUTS(_PATH_PROCNET_UDP6, "udp6");
		//usleep(100000);
		//printf("Tcp6 file content:\n");
	    for(i = 0; i < LH.Hps1->DataItemNum; i++)
	    {
	    	struct IP6PortMessage *IPM = LH.Hps1->portmsg2 + i;
	        //printf("%08X %08X %08X %08X %X  %d\n", IPM->local_addr[0], IPM->local_addr[1],IPM->local_addr[2], IPM->local_addr[3], IPM->local_port, IPM->cur_uid);
	    }//for
	    //printf("scan tcp6 times:%d\n", LH.ps1count);

	    //printf("Tcp file content:\n");
	    for(i = 0; i < LH.Hps2->DataItemNum; i++)
	    {
	    	struct IP4PortMessage *tcp = LH.Hps2->portmsg1 + i;
	    	//printf("%X %X %d\n", tcp->local_addr, tcp->local_port, tcp->cur_uid);
	    }
	   // printf("scan tcp times:%d\n", LH.ps2count);

	    //printf("Udp file content:\n");
	    for(i = 0; i < LH.Hps3->DataItemNum; i++)
	    {
	    	struct IP4PortMessage *udp = LH.Hps3->portmsg1 + i;
	    	//printf("%X %X %d\n", udp->local_addr, udp->local_port, udp->cur_uid);
	    }
	    //printf("scan udp times:%d\n", LH.ps3count);

	    //printf("Udp6 file content:\n");
	    for(i = 0; i< LH.Hps4->DataItemNum; i++)
	    {
	    	struct IP6PortMessage *udp6 = LH.Hps4->portmsg2 + i;
	    	//printf("%08X %08X %08X %08X %X %d\n", udp6->local_addr[0], udp6->local_addr[1], udp6->local_addr[2], udp6->local_addr[3], udp6->local_port, udp6->cur_uid);
	    }
	    //printf("scan udp6 times:%d\n", LH.ps4count);


	}
	return ;
}

/*
 * 同java层交互函数，完成相关函数调用
 */
static void* tcpinfo(void* arg){
	//usleep(5000);
	char buffer[8192];
	LH.ps1count = LH.ps2count = LH.ps3count = LH.ps4count = 0;
	LH.Hps1 = LH.Hps2 = LH.Hps3 = LH.Hps3 = LH.Hps4 = LH.Tps1 = LH.Tps2 = LH.Tps3 = LH.Tps4 = NULL;
    //printf("enter snap record!\n");
	/*创建刷新链表结构线程*/
	if(0 != pthread_create(&thread_id1, NULL, RefreshSnap, NULL))
	{
		//printf("Create pthread1 error!\n");
		return NULL;
	}
	/*if(0 != pthread_create(&thread_id2, NULL, analysis, NULL))
	{
		printf("Create pthread2 error!\n");
		return NULL;
	}*/
    analysis();

	printf("Excute succeed!\n");
	return NULL;
}


int node_read_outfile(struct app_msg *app)
{
	//读取结构体
	FILE *fp = fopen("/storage/emulated/0/packet_capture/record.txt","r");
    //printf("enter readfile!\n");
	if (fread(app, (app_msg_len+1)*sizeof(struct app_msg), 1, fp))

	{

		fclose(fp);

		return 1;

	}

	else return 0;
}


int node_write_infile(struct app_msg *node, int len)
{
	//把结构体写入文件
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fopen file qian");
	FILE *fp = fopen("/storage/emulated/0/packet_capture/record.txt", "w");
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fopen file hou");
	if (fwrite(node, len*sizeof(app_msg), 1, fp))

	{
		fclose(fp);

		return 1;

	}

	else return 0;
}


int main(int argc, char* argv[])
{
	if(argc < 6)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "usage:%s <dev> <protocol> <cap_len> <save_path> <file_name>\n", argv[0]);
		return -1;
	}

	int proto = get_protocol_value(argv[2]);
	if(proto < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "unsurpport protocol :%s\n", argv[2]);
		return -1;
	}

/*	pid_t pid = fork();
	if(pid < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fork failed, %s", strerror(errno));
		return -1;
	}*/

/*	if(pid == 0)
	{*/
		/* 保存传入的路径，用于创建统计文件 */
		strcpy(stats_file_dir, argv[4]);
		strcpy(savedir, argv[4]);

		int i;

		/*for(i = 0;i < 300;i++)
		{
			AppMsg->appnm = "";
		}*/

		/*FILE *readid = fopen("/storage/emulated/0/i_record/appuid.txt","r");
        FILE *readname = fopen("/storage/emulated/0/i_record/appname.txt","r");

		//printf("fopen file success!\n");
		读取文件中保存的应用信息记录
		i = 0;
		while(!feof(readid) && !feof(readname))
		{
			//printf("read the record file!");
			fscanf(readid, "%d", &((AppMsg+i)->uid));
			fscanf(readname, "%s", (AppMsg+i)->appnm);
			i++;
		}
		fclose(readid);
		fclose(readname);*/

		app_msg_len = i;
//		for(i = 0; i <= app_msg_len; i++)
//		{
//			printf("start display!\n");
//			printf("read app_uid: %d, app_name: %s\n", (AppMsg+i)->uid, (AppMsg+i)->appnm);
//		}

		signal(SIGINT, stop_capture);
		signal(SIGTERM, stop_capture);
		signal(SIGKILL, stop_capture);
		//printf("start capture, wait stop signal!\n");
        __android_log_print(ANDROID_LOG_INFO, "sprintwind", "in child process, pid:%d", getpid());

        /*if(0 != pthread_create(&thread_id3, NULL, tcpinfo, NULL))
        {
        	//printf("Create pthread3 error!\n");
        	return -1;
        }*/
        //printf("enter start capture!\n");
		if( start_capture(argv[1], proto, atoi(argv[3]), argv[5]) != 0)
		{
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "start capture failed\n");
			return -1;
		}


		//capture_thread(NULL);
/*
	}
	else
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "in parent process, pid:%d", getpid());
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "capture started");
		exit(0);
	}
*/


	//__android_log_print(ANDROID_LOG_INFO, "sprintwind", "capture started, press ESC to stop\n");

	/*int ch;
	while((ch = getchar())!= EOF)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "input:%d\n", ch);
		if(ch == KEY_ESC)
		{
			stop_capture();
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "capture stopped, %d packets captured, saved to file %s\n", total_capture_count, file_name);
			break;
		}
	}*/

	return 0;
}

JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_MainActivity_JNIgetList(JNIEnv* env, jobject obj, jobject userList)
{
	int i;
	struct app_msg *app = (struct app_msg*)malloc(300 * sizeof(struct app_msg));
	memset(app, 0, 300 * sizeof(struct app_msg));
	//class ArrayList
	jclass cls_arraylist = env->GetObjectClass(userList);
	//method in class ArrayList
	jmethodID arraylist_get = env->GetMethodID(cls_arraylist, "get", "(I)Ljava/lang/Object;");
	jmethodID arraylist_size = env->GetMethodID(cls_arraylist, "size", "()I");
	jint len = env->CallIntMethod(userList, arraylist_size);
	//printf("get java ArrayList<AppTrafficModel> object by C++, the length is: %d\n", len);
	for(i = 0; i < len; i++){
		jobject obj_apptra = env->CallObjectMethod(userList, arraylist_get, i);
		jclass cls_apptra = env->GetObjectClass(obj_apptra);
		jmethodID apptra_getUID = env->GetMethodID(cls_apptra, "getUID", "()I");
		jmethodID apptra_getAppName = env->GetMethodID(cls_apptra, "getAppName", "()Ljava/lang/String;");

		jstring appname = (jstring)env->CallObjectMethod(obj_apptra, apptra_getAppName);
		int length = (env)->GetStringUTFLength(appname);
		jboolean b = true;
		const char *namePtr  = env->GetStringUTFChars(appname, &b);
		char rtn[50];
		memcpy(rtn, namePtr, length);
		jint uid = env->CallIntMethod(obj_apptra, apptra_getUID);

        strcpy((app+i)->appnm, rtn);
		(app+i)->uid = uid;
		//printf("appname: %s; appuid: %d\n", (app+i)->appnm, (app+i)->uid);
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "appname: %s,appuid: %d", (app+i)->appnm, (app+i)->uid);
	}

	app_msg_len = i;

	FILE *fid, *fnm;
	fid = fopen("/storage/emulated/0/i_record/appuid.txt", "w+");
	fnm = fopen("/storage/emulated/0/i_record/appname.txt", "w+");

	for(i = 0; i < app_msg_len; i++)
	{
		fprintf(fid, "%d\n", (app+i)->uid);
		fprintf(fnm, "%s\n", (app+i)->appnm);
	}
	fclose(fid);
	fclose(fnm);

	//if (node_write_infile(app, i+1)) printf("file write OK\n");

	return app_msg_len;
}

JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_CaptureActivity_JNIstartCapture(JNIEnv* env, jobject obj, jstring dev, jint proto, jint cap_len)
//int start_capture(char* dev, int proto, int cap_len)
{
	struct sock_fprog fprog;
	struct ifreq interface;
	struct sock_filter filter[] = {
					{ 0x28, 0, 0, 0x0000000c },
					{ 0x15, 0, 3, 0x00000800 },
					{ 0x30, 0, 0, 0x00000017 },
					{ 0x15, 0, 1, proto },
					{ 0x6, 0, 0, cap_len },
					{ 0x6, 0, 0, 0x00000000 }
				    };
	struct pcap_file_header file_header;

	bool bIsCopy = false;

	//jint result = execl("/system/xbin/su", "su", NULL);
	//__android_log_print(ANDROID_LOG_INFO, "sprintwind", "result:%d", result);

	sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "sock_fd:%d", sock_fd);
	if(sock_fd < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "socket failed");
		__android_log_print(ANDROID_LOG_INFO, "sprintwind","errno, %s",strerror(errno));
		return errno;
	}

	/* 输入了设备则进行绑定 */
	if(NULL != dev)
	{
		strncpy(interface.ifr_ifrn.ifrn_name, env->GetStringUTFChars(dev, NULL), IFNAMSIZ);
		if( setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0)
		{
			__android_log_print(ANDROID_LOG_INFO, "sprintwind", "SO_BINDTODEVICE");
			return errno;
		}
	}

	/*设置过滤条件
	fprog.filter = filter;
	fprog.len = sizeof(filter)/sizeof(struct sock_filter);
	if( setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "SO_ATTACH_FILTER");
		return errno;
	}*/


	/* 初始化pcap文件头 */
	init_file_header(&file_header, cap_len);

	/* 生成文件名
	time(&time_now);
	struct tm* now = localtime(&time_now);
	now->tm_year += 1900;
	sprintf(file_name, "%04d%02d%02d%02d%02d%02d.%s", now->tm_year, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec, PCAP_FILE_SUFFIX);*/

	/* 创建pcap文件 */
	file = fopen(file_name, "wb+");
	if(NULL == file)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fopen");
		return errno;
	}

	/* 写入文件头 */
	need_write_len = sizeof(struct pcap_file_header);
	if( fwrite(&file_header, sizeof(char), need_write_len, file) < need_write_len)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "fwrite");
		return errno;
	}

	//printf("write file header %d bytes\n", need_write_len);

	/* 偏移写文件位置到文件头后面 */
	//fseek(file, need_write_len, SEEK_SET);

	/* 分配报文缓冲区 */
	buffer = (char*)malloc(BUFF_SIZE);
	if(NULL == buffer)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "alloc memory for buffer failed\n");
		return -1;
	}

	memset(buffer, 0, BUFF_SIZE);

	ppkthdr = (struct pcap_pkthdr*)buffer;
	ppkt_start = (char*)ppkthdr + PKT_HDR_LEN;

	capture_count = 0;
	need_write_len = 0;
	total_capture_count = 0;

	/*if(0 != pthread_create(&thread_id, NULL, capture_thread, NULL) )
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "create capture thread failed\n");
		return -1;
	}*/

	char stats_file[FILE_NAME_LEN] = {0};

	sprintf(stats_file, "%s/%s", stats_file_dir, STATS_FILE);

	/* 每次开始时，将抓包统计值清零 */
	write_statistics(stats_file, 0);

	if(0 != pthread_create(&thread_id, NULL, print_thread, NULL))
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "create print thread failed\n");
		return -1;
	}

	capture_thread(NULL);

	return 0;
}

JNIEXPORT void JNICALL Java_com_sprintwind_packetcapturetool_CaptureActivity_JNIstopCapture(JNIEnv* env, jobject obj)
//void stop_capture()
{
	capture = 0;
}

JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_CaptureActivity_JNIgetProtoValue(JNIEnv* env, jobject obj, jstring protocol)
{
	jboolean isCopy = false;
	const char* proto = env->GetStringUTFChars(protocol, &isCopy);
	if(NULL == proto)
	{
		return -1;
	}

	if(0==strcmp(proto, "ARP"))
	{
		return ETH_P_ARP;
	}

	if(0==strcmp(proto, "IP"))
	{
		return ETH_P_IP;
	}

	if(0==strcmp(proto, "ALL"))
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "select all the interfaces\n");
		return ETH_P_ALL;
	}

	return -1;
}

JNIEXPORT jstring JNICALL Java_com_sprintwind_packetcapturetool_CaptureActivity_JNIgetInterfaces(JNIEnv* env, jobject obj)
{
	int sock_fd;
	int if_len;
	struct ifconf ifc;
	struct ifreq buf[MAX_INTERFACE_NUM];//接口信息

	if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "socket failed, %s", strerror(errno));
		return NULL;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t) buf;

	if (ioctl(sock_fd, SIOCGIFCONF, (char *) &ifc) == -1)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "ioctl failed");
		return NULL;
	}

	if_len = ifc.ifc_len / sizeof(struct ifreq);//接口数量

	if(if_len <= 0)
	{
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "if_len <= 0");
		return NULL;
	}

	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "if_len:%d", if_len);

	char buff[1024] = {0};
	char* pResult = buff;

	int i = 0;
	for(; i<if_len; i++){
		__android_log_print(ANDROID_LOG_INFO, "sprintwind", "buf[%d]:%s", i, buf[i].ifr_name);
		if(0!=i)
		{
			*pResult = '|';
		}
		strcat(pResult, buf[i].ifr_name);
		pResult += strlen(buf[i].ifr_name);

	}

	pResult = buff;
	close(sock_fd);
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "return jstring");

	return env->NewStringUTF(pResult);
}

/*JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_MainActivity_JNIexcuteCommand(JNIEnv* env, jobject obj, jstring cmd, jstring args)
{
	const char* strCmd = env->GetStringUTFChars(cmd, NULL);
	const char* strArgs = env->GetStringUTFChars(args, NULL);
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "strCmd:%s, strArgs:%s", strCmd, strArgs);

	if(-1 == execl(strCmd, strArgs)){
		return errno;
	}

	return 0;
}*/

JNIEXPORT jstring JNICALL Java_com_sprintwind_packetcapturetool_MainActivity_JNIgetErrorString(JNIEnv* env, jobject obj, jint err)
{
	return env->NewStringUTF(strerror(err));
}

JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_MainActivity_JNIgetRootPermission(JNIEnv* env, jobject obj)
{
	//jint result = execl("/system/xbin/su", "su", NULL);
	jint result = system("su");
	__android_log_print(ANDROID_LOG_INFO, "sprintwind", "result:%d", result);
	return result;
}

#ifdef __cplusplus
}
#endif
