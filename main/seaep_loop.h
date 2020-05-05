#ifndef SEAEP_LOOP_H
#define SEAEP_LOOP_H

#include "resolve_name_list.h"
#include "seaep_eid.h"
#include <rte_mbuf.h>

#define SEAEP_ACTION_REGISTER 0x9
#define SEAEP_ACTION_RESOLVER 0xb
#define SEAEP_ACTION_LOGOUT 0xd
#define SEAEP_ACTION_RNL 0x7
#define SEAEP_ACTION_MEASURE 0x1b //00011011  
#define SEAEP_ACTION_UPDATE_RNL 0x15 //00010101
#define SEAEP_ACTION_REPORT_ERR 23 //00010101

#define MAX_DELAY_TIME 0x0fffffff


#define SEAEP_ACTION_RESPONSE_RNL 0x8 //00001000
#define SEAEP_ACTION_RESPONSE_RIGSTER 0xa//00001010
#define SEAEP_ACTION_RESPONSE_RESOLVE 0xc//00001000
#define SEAEP_ACTION_RESPONSE_LOGOUT 0xe//00001000
#define SEAEP_ACTION_RESPONSE_MEASURE 0x1c //00011100 
#define SEAEP_ACTION_RESPONSE_UPDATE_RNL 0x16 //00010110
#define SEAEP_ACTION_RESPONSE_REPORT_ERR 24 //00010101


#define SEAEP_GATEWAY_PROT 10010
#define SEAEP_GATEWAY_REGISTER_EID 0xfc//11111100
#define SEAEP_GATEWAY_RESPONSE_REGISTER_EID 0xfd//11111101
#define SEAEP_GATEWAY_REQUEST_IPV6NA 0xfe //11111110
#define SEAEP_GATEWAY_RESPONSE_REQUEST_IPV6NA 0xff //11111111

#define SEAEP_GATEWAY_REQUEST_APADDR 0xf8 //11111000
#define SEAEP_GATEWAY_RESPONSE_REQUEST_APADDR 0xf9 //11111001

#define STATUS_OK 1
#define STATUS_FAILED 0


#define NASTR_MAX_LEN 128
#define PROTO_IPV4 4
#define PROTO_IPV6 6
#define PROTO_UDP 17
#define PROTO_SEADP 1 //tentative?
#define PROTO_SEANET 0x99

typedef struct
{
    char src_na_ip[16];
    char dst_na_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int data_len;
    unsigned char *data_buf;
}packet;


#define UDP_HDR_LEN 8
#define SEADP_HDR_LEN 20
#define ID_HDR_LEN 44
#define IPV4_HDR_LEN 20
#define IPV6_HDR_LEN 40

typedef struct {                       //12 Bytes
	unsigned short srcPort;            //16bits Source Port
	unsigned short dstPort;            //16bits Dest Port
	unsigned short totalLenOfPacket;   //16bits Total Length 
	unsigned short checkSum;           //16bits Checksum
}UDP_HDR;

typedef struct {                       //40 Bytes
	unsigned char trafficClass:4,version:4;     //8bits Version:4,TrafficClass:4
	unsigned char flowLable[3];                //24bits TrafficClass:4,FlowLable:20
	unsigned short payloadLength;     		   //16bits payload length
	unsigned char protocol;         		   //8bits Next Header
	unsigned char hopLimit;           	       //8bits HopLimit
	unsigned char srcAddr[16];		           //128bits SourIP       
	unsigned char dstAddr[16];                 //128bits DestIP       
}IPv6_HDR;

#define MIN_APP_PORT 8000
#define MAX_APP_PORT 8999
#define TOTAL_PORT_NUM (MAX_APP_PORT-MIN_APP_PORT)


#define TASK_TIMEOUT 100 //MS
#define  REQUEST_RNL_TIMEOUT 2000 //MS


typedef struct {
    char result;//0Ϊδ����?, 1Ϊ�ɹ��� -1Ϊʧ��
    unsigned short local_port;// ����ÿ������
    char resolution_node_addr[NASTR_MAX_LEN];
} node_list_info;


typedef struct{
    unsigned char type;//һ��ΪSEAEP_ACTION_RESPONSE_RIGSTER��SEAEP_ACTION_RESPONSE_LOGOUT�� SEAEP_ACTION_RESPONSE_RESOLVE
    char finished; // 1Ϊ��ɣ�0Ϊ��ʱ�˳�
    unsigned char eid[20];
    unsigned char node_num;
    node_list_info *node_info;
    na_list_info *na_info;
} Result_info;


typedef int (*Result_func_cb)(void *context, Result_info *info);


typedef struct seaep_action_record_{
    unsigned long long action_time_out;//ms
    Result_info result;
    void *context;
    Result_func_cb cb_func;
    struct seaep_action_record_ *next;
}seaep_action_record;



int  seaep_init(void *ring_context, const char *global_resolve_node, const char *c1_node,  int delay_level, int rnl_update_interval);

int seaep_start_register (char eid[EID_LEN],  void *context,int delayParameter,unsigned char ttl, int isGlobalVisable,Result_func_cb cb_func);

int seaep_start_resolve (char eid[EID_LEN], void *context, int delayParameter,Result_func_cb cb_func);

int seaep_start_unregister (char eid[EID_LEN],void *context, Result_func_cb cb_func);

void seap_loop(struct rte_mbuf *mbuf);

#endif
