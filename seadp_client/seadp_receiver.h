#ifndef SEADP_RECEIVER_H
#define SEADP_RECEIVER_H

#include "seadp_client.h"
#include "list.h"
#include <stdint.h>

#define DEFAULT_RECV_PORT 10000
#define DEFAULT_PORT 9000
#define INIT_RTO 1200
#define DEFAULT_MTU 1250
#define SREQ_RATIO 0.4

typedef struct{
    unsigned long  left_off;
    unsigned long right_off;
    unsigned short packet_num;
}recv_packet_t;


//for req message
typedef struct {
    struct list_head list;
    unsigned long off;
    unsigned long len;
}sreq_t;


//根据right是否等于chunksize判断是未请求部分还是后续添加的需要sreq数据段
typedef struct {
    struct list_head list;
    unsigned long  left_off;
    unsigned long  right_off;
}pre_req_node_t;



typedef struct{
    struct list_head list;
    unsigned long off;
    unsigned  long  len;
}recv_data_node_t;

typedef struct{
    uint64_t send_time;
    unsigned long off;
    unsigned long len;
    unsigned long req_data_size;
    unsigned long packet_number;
    unsigned short seadp_header_len; //长度可变
    unsigned long sreq_num;
    struct list_head sreq_head_list;  //SREQ 链表
    unsigned char * buff;
    struct list_head recv_data_list;
    unsigned char stat; // 0 未初始化，1 未发送，2 已发送 等待接收数据, 3 请求超时 ，4 收到部分数据包，5 请求完成
}req_packet_t;


//很多信息需要第一个数据包收到后才能进行进一步初始化
typedef struct {
    uint32_t MTU;
    struct list_head pre_req_list_head;
    req_packet_t * req_packet[MAX_PACKET_NUMBER]; //请求包数据 用内存换效率 故没有使用链表
    unsigned short send_max_pnum ; //未发送的的最小包序号，以供seadp_output快速找到包
    unsigned short recv_max_num;
}req_info_t;


//seadp main message
typedef struct {
    uint8_t local_eid[20];
    unsigned char Eid[20];
    uint8_t l_ip[16];
    uint8_t d_ip[16];
    uint16_t local_port;
    unsigned short Port;
    uint8_t sf;
    uint8_t cf;
    unsigned long int chunksize;
    unsigned long int recv_data_size;
    uint8_t send_first_req_count;
    uint64_t last_recv_packet_time;
    unsigned long max_off; //已发送最大偏移
    unsigned long max_recv_off;
    // unsigned long pre_req_max_off;
    unsigned short packet_number;  //当前未使用的最小 packet number
    short int RTO_PT;
    unsigned short abandon_packet_number;
    req_info_t * req_info;
    unsigned char * buff;
    struct rte_mempool *pool;
    uint16_t queue_id;
    call_back cb;
    void * cb_ptr;
    void * cc;
    unsigned char stat; //  0表示未初始化，1表示初始化完成 ， 2 have set chunkID,3 finish ,4出错，
}seadp_receiver_info_t;

seadp_info_t * receiver_seadp_info_create(uint8_t local_eid[20],uint8_t local_ip[16], uint8_t chunk_eid[20],uint8_t dst_ip[16],   \
        call_back cb,void *cb_ptr,seadp_info_parameter_t *para,struct rte_mempool *pool,uint16_t queue_id);
#endif
