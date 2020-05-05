#pragma once

#ifndef MULTICAST_AE
#define MULTICAST_AE

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <inttypes.h>
#include <net/if.h> 
#include <rte_ring.h>
#include "Defaults.h"

#define AE_OK 0
#define AE_ERROR -1
#define BUFFER_SIZE 1000
#define MTC_SIG_MTU_LENGTH 1000
#define SRC_PORT 50000
#define DST_PORT 60000
#define MAX_MULTICAST_NUM 100
#define MAX_HOST_NUM_PER_MULTICAST 100

#define HOSTNUM 50 // max num of hosts of each ports
#define PORTNUM 50 // max num of ports
#define SERVERNUM 100 // max num of multicast service
#define FORWARDNUM 5000 // max num of forward entries
#define TRUE 1
#define true 1
#define FALSE 0
#define false 0
#define MSLEN 20 // multicast service length: 20 bytes
#define IP6LEN 16 // ipv6 addr length: 16 bytes
#define PORTLEN 2 // port: 2 bytes
#define MACLEN 6 // mac addr length: 6 bytes
#define BUFFLEN 180

//extern struct app_lcore_params lcore_conf[24];


#define CHECK_INT_RETURN(code, str) \
	if (AE_ERROR == code) { \
		printf("ERROR: %s\n", str); \
		return AE_ERROR; \
	}

#define CHECK_POINTER_RETURN(ptr, str) \
	if (NULL == ptr) { \
		printf("ERROR: %s\n", str); \
		return AE_ERROR; \
	}

typedef int bool;
typedef int BOOL;

typedef struct
{
	uint16_t outport_index[PORTNUM];
	uint32_t outport_num;
}OUT_PORTS;

//struct FORWARD_INFO{};

struct member_query_starter
{
	bool is_multicast;
	bool start; 
};

struct FORWARD
{
	uint8_t multicast_service_eid[MSLEN];
	uint8_t pre_ip[IP6LEN];
	uint16_t inport;
	OUT_PORTS outport;
	struct FORWARD* next;
};

typedef  struct FORWARD FORWARD_INFO;

typedef struct
{
	FORWARD_INFO* forward_info;
	uint32_t forward_num;
}FORWARD_INFO_BASE;

FORWARD_INFO_BASE forward_info_base;
//FORWARD_INFO renamed to FORWARD_INFO

//extern uint32_t forward_num;

typedef struct 
{
	uint8_t mac_addr[MACLEN];
	uint8_t host_ip[IP6LEN];
	//uint32_t count;
	uint8_t count;
}HOST_INFO;

typedef struct 
{
	uint16_t port;
	HOST_INFO hosts[HOSTNUM];
	uint32_t hosts_num;
}PORT_INFO;

struct EDGE_SWITCH
{
	uint8_t multicast_service_eid[MSLEN];
	PORT_INFO ports[PORTNUM];
	uint32_t ports_num;
	struct EDGE_SWITCH* next;
};

typedef struct EDGE_SWITCH EDGE_SWITCH_INFO;

typedef struct
{
	EDGE_SWITCH_INFO* edge_switch_info;
	uint32_t server_num;
}EDGE_SWITCH_INFO_BASE;

EDGE_SWITCH_INFO_BASE edge_switch_info_base;

//extern uint32_t server_num;

bool host_info_base_is_empty();

//enum BOOL {FALSE, TRUE};

//extern FORWARD_INFO_BASE forward_info_base;
//extern HOST_INFO_BASE host_info_base;

struct local_resource {
	char *dev_name;
	char *dev_ip;
	uint8_t switch_ip[16];
	uint32_t mtc_sev_num;
	uint32_t host_num;
	BOOL edge_flag;
	//pthread_t *member_query_thread;
	uint8_t rev_buf[BUFFER_SIZE];
	uint8_t send_buf[BUFFER_SIZE];
};

struct local_resource_app_lcore_params
{
	struct local_resource *lr;
	struct app_lcore_params *conf;
};

typedef struct  {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
} MAC_HEADER;

typedef struct {
	uint32_t version_class_lable;
	uint16_t payload_len;
	uint8_t next_header;
	uint8_t ttl;
	uint8_t src_ip[16];
	uint8_t dst_ip[16];
} IPV6_HEADER;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
} UDP_HEADER;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
} SIGNALLING;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t ip[16];
} SWITCH_INFO_SIG;

typedef struct 
{
	uint8_t proto;
	uint8_t hdr_len;
	uint16_t attr;
	uint8_t src_eid[20];
	uint8_t dst_eid[20];
}EID_HEADER;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
	uint16_t port;
	uint8_t mac[6];
	uint8_t ip[16];
} HOST_INFO_SIG;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
	uint8_t ip[16];
	uint16_t inport;
	uint16_t outport;
} FORWARD_INFO_SIG;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
	uint8_t ip[16];
	uint8_t mac[6];
	uint16_t port_num;
} JOIN_INFO_SIG;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
	uint8_t ip[16];
	uint8_t mac[6];
	uint16_t port_num;
} QUERY_INFO_SIG;

typedef struct {
	uint8_t type_low;
	uint8_t type_high;
	uint16_t len;
	uint8_t eid[20];
	uint16_t port_num;
} ENTRY_UPDATE_INFO_SIG;

typedef struct mc_query_info
{
  UDP_HEADER* udp_hdr;
  MAC_HEADER* mac_hdr;
  IPV6_HEADER* ip_hdr;
  SIGNALLING* sig_hdr;
} mc_query_info;

struct local_resource lr;

int multicast_query_loop(__attribute__((unused)) void *arg);

int quit_sig_query_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, struct local_resource *lr, struct app_lcore_params *conf);

int sendtotxt_multicast(unsigned char *buffer, int bufferlen, struct rte_ring *r);

int sendtotxt_mc_query(unsigned char *buffer, int bufferlen, struct rte_ring *r);

int packet_processor_init(struct local_resource *lr);

int cli_init();

void mySleep(int second);

int ae_task_create(void *arg, void *func_ptr, pthread_t *thread_id_ptr);

int recv_raw_task(struct local_resource *lr);

//int send_packet(uint8_t *buf, uint32_t buf_len, struct local_resource *lr);
//20191211

uint8_t * udp_packet_constructor(uint8_t *src_mac, uint8_t *dst_mac, uint8_t *src_ip, uint8_t *dst_ip, uint8_t *sig, uint32_t sig_len, uint32_t *buf_len);

uint8_t * join_info_constructor(uint8_t *eid, uint8_t *mac, uint8_t *ip, uint16_t port_num, uint16_t *port_list, uint32_t *buf_len);

uint8_t * entry_update_info_constructor(uint8_t *eid, uint16_t port_num, uint16_t *port_list, uint32_t *buf_len);

uint8_t * signalling_constructor(uint8_t type_low, uint8_t type_high, uint8_t *eid, uint32_t* buf_len);

uint8_t * switch_info_constructor(uint8_t *ip);

uint8_t * host_info_constructor(uint16_t port, uint8_t *mac, uint8_t *ip,  uint8_t *eid);

uint8_t * multicast_forward_info_constructor(uint8_t *eid, uint8_t *ip, uint16_t inport, uint16_t outport);



int join_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, uint8_t *raw_pkt, uint32_t raw_pkt_len, struct local_resource *lr, struct app_lcore_params *conf);

int quit_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, struct local_resource *lr, struct app_lcore_params *conf);

int prune_sig_handler(uint8_t *eid, uint16_t port, struct local_resource *lr, struct app_lcore_params *conf);

int reply_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip);

int switch_info_sig_handler(uint8_t *sig, struct local_resource *lr);

int host_info_sig_handler(uint8_t *sig, struct local_resource *lr, struct app_lcore_params *conf);

int fwd_info_sig_handler(uint8_t *sig);

int error_handler();

int clear_multicast_info(uint8_t *eid);

int start_member_query(struct local_resource_app_lcore_params *lr_conf);

int member_query(struct local_resource_app_lcore_params *lr_conf);

BOOL is_multicast_in_forward_info_base(uint8_t *eid);
//function-1: ok

uint16_t * get_outports_from_forward_info_base(uint8_t *eid, uint16_t *port_num);
//function-2: ok

uint16_t * get_outports_from_forward_info(FORWARD_INFO *fwd_info, uint16_t *port_num);
//function-3: ok

FORWARD_INFO * get_forward_info_from_forward_info_base(uint8_t *eid);
//function-4: ok

int forward_info_base_add_multicast(uint8_t *eid, uint8_t *pre_ip, uint16_t inport, uint16_t outport);
//function-5: ok

int forward_info_base_delete_multicast(uint8_t *eid);
//function-6: ok

int forward_info_base_delete_outport(uint8_t* eid, uint16_t port);
//function-20

int forward_info_delete_outport(FORWARD_INFO *fwd_info, uint16_t port_num);
//function-7: ok

int forward_info_add_outport(FORWARD_INFO *fwd_info, uint16_t outport);
//function-8: ok

int host_info_base_delete_multicast(uint8_t *eid);
//function-15: ok

int host_info_base_add_host(uint8_t *eid, uint16_t port, uint8_t *mac, uint8_t *ip);
//function-16: ok

EDGE_SWITCH_INFO * get_edge_switch_info_from_host_info_base(uint8_t *eid);
//function-17: ok

HOST_INFO * get_host_info_from_host_info_base(uint8_t *eid, uint8_t *mac, uint8_t *ip);
//function-14: ok

int get_outport_num_from_host_info_base(uint8_t *eid);
//function-18: ok

int host_info_base_delete_port(uint8_t *eid, PORT_INFO *port_info);
//function-19

HOST_INFO* get_host_info_from_edge_switch_info(EDGE_SWITCH_INFO *edge_switch_info, uint8_t *mac, uint8_t *ip);
//function-13: ok

PORT_INFO* get_port_info_from_edge_switch_info(EDGE_SWITCH_INFO *edge_switch, HOST_INFO *host);
//function-12: ok

int edge_switch_info_delete_port(EDGE_SWITCH_INFO *edge_switch, PORT_INFO *port);
//function-11: ok

int port_info_delete_host(PORT_INFO *port, HOST_INFO *host);
//function-10: ok

int host_info_clear_counter(HOST_INFO* host);
//function-9: ok

int info_base_init();

int check_device(char *interface);

int check_root();

int check_interface_fromproc(char *interface);

int packet_parser(uint8_t *raw_pkt, uint32_t len, struct local_resource *lr, struct app_lcore_params *conf);

int multicast_ae_init(struct local_resource *lr);

#endif