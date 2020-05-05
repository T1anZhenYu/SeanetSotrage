#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
//#include<netinet/in.h>
#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#define MAX_SREQ 20  // max sreq number

typedef struct {
  unsigned char EID[20];
  unsigned char ack_n;             // 8bits offset numbers
  unsigned long offset[MAX_SREQ];  // offset left
  unsigned long size[MAX_SREQ];    // offset lengsth
} rcv_inf;

typedef struct {             // 44 Bytes
  unsigned char next;        // 8bits NextVersion
  unsigned char len;         // 8bits Length
  unsigned short attr;       // 16bits Attribute
  unsigned char srcEid[20];  // 20bytes Source EID
  unsigned char dstEid[20];  // 20bytes Dest EID
  // options
} __attribute__((__packed__)) ID_HDR;



typedef struct {                         // 20 Bytes
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
} __attribute__((__packed__)) SEADP_HDR;

typedef struct {       // TLV
  unsigned char type;  // 8bits TLV type
  unsigned char len;   // 8bits TLV lenth
  // tag_node *pnode;                     //
  unsigned long off[MAX_SREQ];   // SREQ offset left
  unsigned long size[MAX_SREQ];  // SREQ offset lenth
} SEADP_HDR_SREQ;


unsigned short fill_seadp_checksum(SEADP_HDR *seadp_header, size_t payload_len);

static unsigned long seadp_checksum(unsigned short *buffer, size_t size);
static unsigned short finish_checksum(unsigned long cksum);
unsigned long header_checksum(SEADP_HDR *seadp_header);
unsigned long payload_checksum(unsigned short *payload_buff,
                               size_t payload_len);

int rcv_parse(const struct rte_mbuf *packet,
              rcv_inf *inf);  // 0=success -1=failure

int32_t rcv_send(const struct rte_mbuf *packet, struct rte_mbuf *send_packet,
                 const unsigned char *data, unsigned long chunk_size,
                 unsigned long off, unsigned long size, int32_t p);