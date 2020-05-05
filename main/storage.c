#include <arpa/inet.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#define MOBILE_LOG(...) printf("[MOBILE LOG]: " __VA_ARGS__)

#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define APP_DELAY_LEVEL 3

#define MOBILE_TYPE 100  //发包移动标识

#define EID_LEN 20

#define ETH_LEN 14
#define IP_LEN 20
#define ID_LEN 44
#define REG_LEN 27

#define POF_HEADER_LEN 8
#define POF_PACKET_IN_BEFORE_LEN 24
#define IPV6_LEN 40
#define UDP_LEN 8
#define MOBILE_BEFORE_EID_LEN 20

#define BUFFSIZEMOBI 118

#define BUFFSIZEMOBF 104
#define BUFFSIZEMOBFR 120
#define BUFFSIZERESOLVES 101
#define BUFFSIZERESOLVEF 85

#define RESNUM 1
#define DELAYTIME 20  // meta的延时参数ms

#define SEAEP_RESULT_FAILED 0
#define SEAEP_RESULT_SUCCESS 1

typedef struct eth_header {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  unsigned char proto[2];
} eth_header;

typedef struct ipv6_header {
  unsigned char version_TypeofService_FlowTag[2];  // 16 bits
  unsigned char FlowTag[2];                        // 16bits
  unsigned char payloadLen[2];                     // 16bits,2B
  unsigned char nextHeader;                        // 8bits,1B
  unsigned char hopLimit;                          // 8bits,1B
  unsigned int srcipv6[4];                         // 128bits
  unsigned int dstipv6[4];                         // 128bits
} ipv6_header;


typedef struct eid_header {
  unsigned char proto;       // 1B
  unsigned char hdr_len;     // 1B
  unsigned short attr;       // 2B
  unsigned char srcEid[20];  // 20B
  unsigned char dstEid[20];  // 20B
} eid_header;
typedef struct eid_header2 {
  unsigned char proto;       // 1B
  unsigned char hdr_len;     // 1B
  unsigned short attr;       // 2B
  unsigned char srcEid[20];  // 20B
  unsigned char dstEid[20];  // 20B
  unsigned char dst2Eid[20];  // 20B
} eid_header2;

typedef struct res_ack {
  unsigned char type;
  unsigned char status;
  unsigned char eid[EID_LEN];  // eid
  unsigned char num;
  // unsigned int new_ip[4];  //16B
} res_ack;

typedef struct mobmess_hdr {
  unsigned char mes_type;              // 1B
  unsigned char mes_version_reserved;  // 1B
  unsigned short mes_checksum;         // 2B
  unsigned char payload_len[2];        // 2B
  // unsigned char newna[16];//16B
} mobmess_hdr;  // 6B

typedef struct sendeid {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct eid_header eid_hdr;
  struct mobmess_hdr mobmesshdr;
  unsigned char eid[EID_LEN];  //告知服务端eid
} sendeid;

typedef struct ack_sendeid {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct eid_header eid_hdr;
  struct mobmess_hdr mobmesshdr;
} ack_sendeid;

int main(){
    eid_header2 *e2 = (eid_header2*)malloc(sizeof(eid_header2));
    strncpy((char*)e2->srcEid,"aaaaaaaaaaaaaaaaaaaaaaaaa",19);
    e2->srcEid[19]='\0';
    strncpy((char*)e2->dstEid,"bbbbbbbbbbbbbbbbbbbbbbbbbbb",19);
    e2->dstEid[19]='\0';
    strncpy((char*)e2->dst2Eid,"cccccccccccccccccccccccccccc",20);
    e2->dst2Eid[19]='\0';
    eid_header *e1;
    e1 = (eid_header*)e2;
    printf((char*)e1->dstEid);
    printf("\n");

}