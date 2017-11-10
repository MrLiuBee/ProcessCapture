/*
 * Copyright (C) 2017 The Android Process Packet Capture Project
 * 解析系统文件/proc/net/tcp,tcp6,udp,udp6,获取应用UID和流量端口的对应关系。
 */
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
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <android/log.h>
#include "port_map.h"

#define _PATH_PROCNET_TCP "/proc/net/tcp"
#define _PATH_PROCNET_TCP6 "/proc/net/tcp6"
#define _PATH_PROCNET_UDP "/proc/net/udp"
#define _PATH_PROCNET_UDP6 "/proc/net/udp6"

struct LinkHead LH;
FILE* procinfo;
struct timeval ts, tv;
pthread_t thread_id;
int count1 = 0;
int count2 = 0;
int count3 = 0;
int count4 = 0;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 从链表中删除节点
 */
static int DeleteEleLinkList(struct PortScanner *p){
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

while(1)
{
	/*每隔一分钟扫描一次*/
	sleep(60000);
	/*获取当前系统时间*/
	gettimeofday(&tv, NULL);
	curtime = tv.tv_usec / 1000 + tv.tv_sec * 1000;

	/*删除tcp6快照记录中大于1minute的节点*/
	ps1 = ps = LH.Hps1;
	while(!ps1){
		if(curtime-ps1->time_usec_start > 60000)
		{
			ps1 = ps->nextcur;
			DeleteEleLinkList(ps);
			ps = ps1;
		}//if
		ps1 = ps = ps1->nextcur;
	}//while

	/*删除tcp快照记录中大于1minute的节点*/
	ps2 = ps = LH.Hps2;
	while(!ps2){
		if(curtime-ps2->time_usec_start > 60000)
		{
			ps2 = ps->nextcur;
			DeleteEleLinkList(ps);
			ps = ps2;
		}//if
		ps2 = ps = ps2->nextcur;
	}//while

	/*删除udp快照记录中大于1minute的节点*/
	ps3 = ps = LH.Hps3;
	while(!ps3){
		if(curtime-ps3->time_usec_start > 60000)
		{
			ps3 = ps->nextcur;
			DeleteEleLinkList(ps);
			ps = ps3;
		}//if
		ps3 = ps = ps3->nextcur;
	}//while

	/*删除udp6中快照记录中大于1minute的节点*/
	ps4 = ps = LH.Hps4;
	while(!ps4){
		if(curtime-ps4->time_usec_start > 60000)
		{
			ps4 = ps->nextcur;
			DeleteEleLinkList(ps);
			ps = ps4;
		}//if
		ps4 = ps = ps4->nextcur;
	}//while

}//while(1)

	return NULL;
}

/*
 * tcp数据存储函数，将tcp缓冲区中的内容写入到存储结构中
 */
static void tcp_do_one(char *buffer,char *ftype, struct PortScanner *pscan, int change){
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128];
	struct IP6PortMessage *pt2;
	struct IP4PortMessage *pt1;

	num = sscanf(buffer,
	"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
	     &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	     &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

	if(num < 11){
		fprintf(stderr, ("warning, got bogus tcp line.\n"));
		return;
	}

	if(strlen(local_addr) > 8){
//#if HAVE_AFINET6
	/*纠正内核给我们的信息内容*/
	pt2 = pscan->portmsg2 + change;
	sscanf(local_addr, "%08X%08X%08X%08X",
			&pt2->local_addr[0], &pt2->local_addr[4],
			&pt2->local_addr[8], &pt2->local_addr[12]);
	pt2->local_port = local_port;

	sscanf(rem_addr, "%08X%08X%08X%08X",
			&pt2->remote_addr[0], &pt2->remote_addr[4],
			&pt2->remote_addr[8], &pt2->remote_addr[12]);
	pt2->remote_port = rem_port;
	pt2->cur_uid = uid;
//#endif
	}
	else{
		pt1 = pscan->portmsg1 +change;
		sscanf(local_addr, "%X", &pt1->local_addr);
		sscanf(rem_addr, "%X", &pt1->remote_addr);
		pt1->local_port = local_port;
		pt1->remote_port = rem_port;
		pt1->cur_uid = uid;
	}

}

/*
 * 读取系统文件（tcp,tcp6,udp,udp6），文件内容暂存到buffer缓冲区中
 * 并最后将缓冲区内容写入到建立的存储结构中
 */
static int INFO_GUTS(char *file,char *filetype){
	int tag = -1;
	int incrlen = 0;
	int change = 0;
	int totallen = INIT_LINKLIST_LENGTH;
	char buffer[8192];
	struct IP6PortMessage *top6 = (struct IP6PortMessage*)malloc(sizeof(struct IP6PortMessage));
	struct IP4PortMessage *top4 = (struct IP4PortMessage*)malloc(sizeof(struct IP4PortMessage));

	/*建立快照存储结构头结点*/
	struct PortScanner *pscan = (struct PortScanner*)malloc(sizeof(struct PortScanner));
	if(filetype == "tcp6")
	{
		if(LH.ps1count == 0)
		{
			LH.Hps1 = LH.Tps1 = pscan;
			//pscan->precur = &LH;
			pscan->nextcur = NULL;
		}
		else
		{
			pscan->precur = LH.Tps1;
			pscan->nextcur = NULL;
			LH.Tps1->nextcur = pscan;
			LH.Tps1 = pscan;
		}

	}
	else if(filetype == "tcp")
	{
		if(LH.ps2count == 0)
		{
			LH.Hps2 = LH.Tps2 = pscan;
			//pscan->precur = &LH;
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
		if(LH.ps3count == 0)
		{
			LH.Hps3 = LH.Tps3 = pscan;
			//pscan->precur = &LH;
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
		if(LH.ps4count == 0)
		{
			LH.Hps4 = LH.Tps4 =pscan;
			//pscan->precur = &LH;
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

	procinfo = fopen(file, "r");
	if(procinfo == NULL){
		return -1;
	}

	/*写入快照结点开始时间*/
	gettimeofday(&ts,NULL);
	pscan->time_usec_start = ts.tv_usec / 1000 + ts.tv_sec * 1000;

	/*循环读取并处理系统文件*/
	do{
		if(tag == 1)
		{
			if(top6-pscan->portmsg2 >= totallen){
				pscan->portmsg2 = (struct IP6PortMessage*)realloc(pscan->portmsg2, (totallen+LATER_INCRE_LENGTH)*sizeof(struct IP6PortMessage));
				top6 = pscan->portmsg2 + totallen;
			}
		}
		else if(tag == 0)
		{
			if(top4-pscan->portmsg1 >= totallen){
				pscan->portmsg1 = (struct IP4PortMessage*)realloc(pscan->portmsg1, (totallen+LATER_INCRE_LENGTH)*sizeof(struct IP4PortMessage));
			    top4 = pscan->portmsg1 + totallen;
			}
		}
		if(!top4 || !top6)
		{
			printf("realloc failed!");
			return -1;
		}

		totallen += LATER_INCRE_LENGTH;


		if(fgets(buffer, sizeof(buffer), procinfo))
		{
			tcp_do_one(buffer, filetype, pscan, incrlen);
			incrlen++;
		}
	}while(!feof(procinfo));

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
 * 同java层交互函数，完成相关函数调用
 */
JNIEXPORT jint JNICALL Java_com_sprintwind_packetcapturetool_CaptureActivity_JNItcpinfo(JNIEnv* env, jclass clazz){
	char buffer[8192];
	LH.ps1count = LH.ps2count = LH.ps3count = LH.ps4count = 0;
	LH.Hps1 = LH.Hps2 = LH.Hps3 = LH.Hps3 = LH.Hps4 = LH.Tps1 = LH.Tps2 = LH.Tps3 = LH.Tps4 = NULL;
    printf("enter snap record!\n");
	/*创建刷新链表结构线程*/
	if(0 != pthread_create(&thread_id, NULL, RefreshSnap, NULL))
	{
		printf("Create pthread error!\n");
		return -1;
	}
	while(1)
	{
		INFO_GUTS(_PATH_PROCNET_TCP, "tcp6");
		INFO_GUTS(_PATH_PROCNET_UDP, "tcp");
		INFO_GUTS(_PATH_PROCNET_TCP6, "udp");
		INFO_GUTS(_PATH_PROCNET_UDP6, "udp6");
        for(int i = 0; i < LH.ps1count; i++)
        {
        	printf("%s  %X  %d\n", LH.Hps1->portmsg2->local_addr, LH.Hps1->portmsg2->local_port, LH.Hps1->portmsg2->cur_uid);
        }//for
	}

	return 1;
}

/*static JNINativeMethod gMethods[] = {
	{"nativeTcp_Info", "(I)J", (void*)tcp_info}
};*/

#ifdef __cplusplus
}
#endif
