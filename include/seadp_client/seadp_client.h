#ifndef SEADP_CLIENT_H
#define SEADP_CLIENT_H

// #include "seadp.h"
#include <endian.h>
#include <stddef.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_log.h>

#define DBG_LEVEL   DBG_LEVEL_TRACE

#define DBG_LEVEL_TRACE		1
#define DBG_LEVEL_WARNING	2
#define DBG_LEVEL_ERROR		3
#define DBG_LEVEL_SILENT	4

#define SEADP_POS

#define SEADP_DBG(level,fmt,args...)  \
do{ \
    if(level>=DBG_LEVEL)  \
        RTE_LOG(ERR, USER1, "[SeaDP log at %s,%s,%d]:" fmt "\n",__FILE__,__FUNCTION__,__LINE__,##args); \
}while(0); 



#define EID_LEN 20
#define PROTO_IPV4 4
#define PROTO_IPV6 6
#define PROTO_UDP 17
#define PROTO_SEADP 0x01 //tentative?
#define PROTO_SEANET 0x99

#define UDP_HDR_LEN 8
#define SEADP_HDR_LEN 20      //temp
#define ID_HDR_LEN 44
#define IPV4_HDR_LEN 20
#define IPV6_HDR_LEN 40

#define MAX_PACKET_NUMBER 65535

#define RECEIVER 0
#define SENDER 1

// #define SEADP_INPUT_RING "seadp input ring"
// #define SEADP_OUTPUT_RING "seadp output ring"

typedef struct {                       //44 Bytes
    unsigned char next;                //8bits NextVersion
    unsigned char len;                 //8bits Length
    unsigned short attr;               //16bits Attribute
    unsigned char srcEid[20];          //20bytes Source EID
    unsigned char dstEid[20];          //20bytes Dest EID
    //options
}id_hdr_t;

typedef struct {                       //40 Bytes
    unsigned char trafficClass:4,version:4;     //8bits Version:4,TrafficClass:4
    unsigned char flowLable[3];                //24bits TrafficClass:4,FlowLable:20
    unsigned short payloadLength;              //16bits payload length
    unsigned char protocol;                    //8bits Next Header
    unsigned char hopLimit;                    //8bits HopLimit
    unsigned char srcAddr[16];                 //128bits SourIP
    unsigned char dstAddr[16];                 //128bits DestIP
}ipv6_hdr_t;

enum {
    REQ=32,
    DAT=8,
    CDAT=16,
    CFIN=4,
    CREQ=64
};
typedef struct{                          //20 Bytes
    unsigned short srcPort;              //16bits source port
    unsigned short dstPort;              //16bits dest port
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char sdat:1，pflag:7;   //8bits Version:4,reserve:4
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char pflag:7,sdat:1;   //8bits Version:4,reserve:4
#endif
    unsigned char hdrlen;                 //8bits packet flag(DAT\REQ)
    unsigned char cflag;                 //8bits cache flag
    unsigned char sflag;                 //8bits storage flag
    unsigned short packetnumber;          //8bits packet number
    unsigned short checksum;             //16bits seadp packet checksum
    unsigned int off;                    //32bits offset
    unsigned int len;                    //32bits total length,chunk size
    // unsigned int flow_chunk_num;          //
}seadp_hdr_t;

typedef enum {
    TLV_SREQ,
    TLV_TIMESTAMP,
    TLV_MTU,
    TLV_NOP
}tlv_optname_t;

typedef struct {
    void *info;//指向seadp_receiver_info_t或seadp_sender_info_t
    int (*heartbeat)           (void * info);   // -1 error 对于接收端返回值为0至100之间的某个数，表示chunk接收进度，对发送端来说正在运行为0
    void (*process_packets)     (void * info,struct rte_mbuf *m_packet);
    int  (*get_status)          (void * info);
    void (*close)               (void * info); 
}seadp_info_t;

typedef struct{
    uint8_t sf;
    uint8_t cf;
    uint16_t dstport;
}seadp_info_parameter_t;



typedef int (*call_back)(void *cb_ptr,uint8_t eid[20], uint8_t *buf,uint32_t buf_len);
//seadp 提供的接口
void * seadp_init(uint8_t local_eid[20],uint8_t local_ip[16],struct rte_mempool *pool,uint16_t queue_id);
int seadp_create_task(void *seadp_ptr,uint8_t eid[20],uint8_t ip[16],call_back cb ,void * cb_ptr);
void seadp_process_packets(void *seadp_ptr,struct rte_mbuf *mbuf);
void seadp_heartbeat(void *seadp_ptr);
int seadp_cancel_task(void *seadp_ptr,uint8_t eid[20]);
int seadp_get_task_status(void *seadp_ptr,uint8_t eid[20]); //error -1 ,not find -2, >=0 normal
int seadp_set_option(void *seadp_ptr, int type,uint8_t *buf ,int len);




int get_seadp_checksum(seadp_hdr_t *seadp_header,unsigned char *payload_buff,size_t payload_len);
uint64_t get_time_ms();

#endif
