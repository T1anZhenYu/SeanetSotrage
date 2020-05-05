#include "dpdk_rcv.h"
#include "rte_byteorder.h"

#define ETHER_TYPE_IPv4_BE 0x0008 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6_BE 0xDD86 /**< IPv6 Protocol. */

#define EID_LEN 20

#define ETH_HEAD_LEN 14
#define IPV4_HDR_LEN 20
#define IPV6_HDR_LEN 40
#define ID_HDR_LEN 44
#define SEADP_HDR_LEN 20
#define SEANET_PROT 0x99
#define SEADP_PROT 0x01
#define    REQ 32
#define    DAT 8
#define    CDAT 16
#define   CFIN 4
#define    CREQ 64

#define TOTAL_HEADER_SIZE \
  (SEADP_HDR_LEN + ID_HDR_LEN + IPV6_HDR_LEN + ETH_HEAD_LEN)

// checksum
static unsigned long seadp_checksum(unsigned short *buffer, size_t size) {
  unsigned long cksum = 0;
  

  while (size > 1) {
    cksum += *buffer++;
    size -= sizeof(unsigned short);
  }
  if (size) {
    cksum += *(unsigned char *)buffer;
  }
 
  return cksum;
}
static unsigned short finish_checksum(unsigned long cksum) {
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return (unsigned short)(~cksum);
}

  
    unsigned long header_checksum(SEADP_HDR *seadp_header) {
      unsigned long a = seadp_checksum((unsigned short *)&seadp_header->srcPort, 6);
  unsigned long b =
          seadp_checksum((unsigned short *)&seadp_header->packetnumber,
                         seadp_header->hdrlen - 8);
  return a + b;
}
unsigned long payload_checksum(unsigned short *payload_buff,
                                size_t payload_len) {
  return seadp_checksum((unsigned short *)payload_buff, payload_len);
}

unsigned short fill_seadp_checksum(SEADP_HDR *seadp_header,size_t payload_len) {
  unsigned short *p = (unsigned short *)seadp_header;
  unsigned long checksum;
  if (payload_len == 0) {
      checksum=header_checksum(seadp_header);
    return finish_checksum(checksum);
  } else {
    checksum=(header_checksum(seadp_header)) +
           (payload_checksum((p+10),payload_len));
    return finish_checksum(checksum);
  }
}

// parse REQ package
int rcv_parse(const struct rte_mbuf *packet,
              rcv_inf *inf)  // 0=success -1=failure
{
  struct ether_hdr *eth_hdr;
  struct ipv6_hdr *ipv6_hdr;
  ID_HDR *id_hdr;
  SEADP_HDR *seadp_hdr;
  SEADP_HDR_SREQ *sreq;
  uint8_t seadp_hdrlen;
  uint16_t MTU = 0;

  eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
  //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
  if (eth_hdr->ether_type != ETHER_TYPE_IPv6_BE) {
    fprintf(stderr, "%s:%d entry = %04x\n", __FILE__, __LINE__,
            eth_hdr->ether_type);
    return -1;
  }

  ipv6_hdr = (struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
  if (ipv6_hdr->proto != SEANET_PROT) {
    fprintf(stderr, "%s:%d entry = %02x\n", __FILE__, __LINE__,
            ipv6_hdr->proto);
    return -1;
  }

  id_hdr = (ID_HDR *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct ipv6_hdr));

  if (id_hdr->next != SEADP_PROT) {
    fprintf(stderr, "%s:%d entry = %02x\n", __FILE__, __LINE__, id_hdr->next);
    return -1;
  }
 // fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);

  seadp_hdr = (SEADP_HDR *)RTE_PTR_ADD(id_hdr, sizeof(ID_HDR));
  seadp_hdrlen = seadp_hdr->hdrlen;

  //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
  while ((seadp_hdrlen - 20) != 0)  // seadp has TLVs(SREQs)
  { 
    if (seadp_hdrlen < 20) {
      return -1;
    }
    unsigned char * tlv_hdr  = (unsigned char *)RTE_PTR_ADD(seadp_hdr, sizeof(SEADP_HDR));
    unsigned char tlv_type = *(tlv_hdr);//TLV-type 
    unsigned char tlv_len  = *((unsigned char *)(tlv_hdr + 1));//TLV-length, the whole length of TLV
    unsigned char * tlv_value= (unsigned char *)(tlv_hdr + 2);//TLV-value
    if (tlv_len == 0) { 
      return -1;
    }
    if (( tlv_type ) == 1) {
      sreq = (SEADP_HDR_SREQ *)tlv_hdr;
      rte_memcpy(inf->EID, id_hdr->dstEid, 20);
      inf->ack_n = (1 + (sreq->len));
      inf->offset[0] = ntohl(seadp_hdr->off);
      inf->size[0] = ntohl(seadp_hdr->len);
      rte_memcpy(inf->offset + 1, sreq->off, 20);
      rte_memcpy(inf->size + 1, sreq->size, 20);
      fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
      return 0;
    };
    if ((tlv_type) == 3) {
      MTU = ntohs((uint16_t *) tlv_value);
    }
    if (MTU == 0) {
      return -1;
    }
    seadp_hdrlen = seadp_hdrlen - tlv_len;
    tlv_hdr = tlv_hdr + tlv_len;
  };
  //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);

  rte_memcpy(inf->EID, id_hdr->dstEid, 20);  // seadp doesn't have TLVs(SREQ)
  inf->ack_n = 1;
  inf->offset[0] = ntohl(seadp_hdr->off);
  inf->size[0] = ntohl(seadp_hdr->len);
  if (inf->size[0] == 0) {
    inf->size[0] = MTU - TOTAL_HEADER_SIZE;
  }
 // fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
  return 0;
};

int32_t rcv_send(const struct rte_mbuf *packet, struct rte_mbuf *send_packet,
                 const unsigned char *data, unsigned long chunk_size,
                 unsigned long off, unsigned long size,
                 int32_t p)  // p=-1 error;p=0  send over;p>0 sending
{
  struct ether_hdr *eth_hdr, *eth_hdr_s;   //（_s means send）  4 bytes
  struct ipv6_hdr *ipv6_hdr, *ipv6_hdr_s;  // 10 bytes
  ID_HDR *id_hdr, *id_hdr_s;               // 44 bytes
  SEADP_HDR *seadp_hdr, *seadp_hdr_s;      // 20 bytes
  char *payload_hdr;                       // 
  uint8_t seadp_hdrlen;
  unsigned char *tlv_hdr;
  uint16_t MTU = 0;
  uint16_t MSS;  // MTU-headersize

  //fprintf(stderr, "chunk size = %d, off = %d, size = %d, p = %d\n", chunk_size,
  //        off, size, p);

  // init send_packet
  eth_hdr_s = rte_pktmbuf_mtod(send_packet, struct ether_hdr *);
  ipv6_hdr_s =(struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr_s, sizeof(struct ether_hdr));
  id_hdr_s = (ID_HDR *)RTE_PTR_ADD(ipv6_hdr_s, sizeof(struct ipv6_hdr));
  seadp_hdr_s = (SEADP_HDR *)RTE_PTR_ADD(id_hdr_s, sizeof(ID_HDR));

  // ethernet header
  eth_hdr = rte_pktmbuf_mtod(packet, struct ether_hdr *);
  if (eth_hdr->ether_type != ETHER_TYPE_IPv6_BE) {
    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    return -1;
  }
  *eth_hdr_s = *eth_hdr;
  rte_memcpy(eth_hdr_s->s_addr.addr_bytes, eth_hdr->d_addr.addr_bytes, 6);
  rte_memcpy(eth_hdr_s->d_addr.addr_bytes, eth_hdr->s_addr.addr_bytes, 6);

  // ip header
  ipv6_hdr = (struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
  if (ipv6_hdr->proto != SEANET_PROT) {
    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    return -1;
  }
  *ipv6_hdr_s = *ipv6_hdr;
  rte_memcpy(ipv6_hdr_s->src_addr, ipv6_hdr->dst_addr, 16);
  rte_memcpy(ipv6_hdr_s->dst_addr, ipv6_hdr->src_addr, 16);

  // id header
  id_hdr = (ID_HDR *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct ipv6_hdr));

  if (id_hdr->next != SEADP_PROT) {
    fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    return -1;
  }
  *id_hdr_s = *id_hdr;
  rte_memcpy(id_hdr_s->srcEid, id_hdr->dstEid, 20);
  rte_memcpy(id_hdr_s->dstEid, id_hdr->srcEid, 20);

  // seadp header
  seadp_hdr = (SEADP_HDR *)RTE_PTR_ADD(id_hdr, sizeof(ID_HDR));

  seadp_hdrlen = seadp_hdr->hdrlen;
  *seadp_hdr_s = *seadp_hdr;
  seadp_hdr_s->srcPort = seadp_hdr->dstPort;
  seadp_hdr_s->dstPort = seadp_hdr->srcPort;
  if(p==0){
    seadp_hdr_s->pflag =CDAT;
  };
  seadp_hdr_s->hdrlen = 20;
  seadp_hdr_s->checksum = 0;
  seadp_hdr_s->off = rte_cpu_to_be_32(p + off);
  seadp_hdr_s->len = rte_cpu_to_be_32(chunk_size);

  // while has tlv header,get MTU
  //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
  while ((seadp_hdrlen - 20) != 0)  // seadp has TLVs(SREQs)
  { 
    if (seadp_hdrlen < 20) {
      return -1;
    }
    unsigned char * tlv_hdr  = (unsigned char *)RTE_PTR_ADD(seadp_hdr, sizeof(SEADP_HDR));
    unsigned char tlv_type = *(tlv_hdr);//TLV-type 
    unsigned char tlv_len  = *((unsigned char *)(tlv_hdr + 1));//TLV-length, the whole length of TLV
    unsigned char * tlv_value= (unsigned char *)(tlv_hdr + 2);//TLV-value
    if (tlv_len == 0) { 
      return -1;
    }
    if ((tlv_type) == 3) {
      MTU = ntohs((uint16_t *) tlv_value);
    }
    if (MTU == 0) {
      return -1;
    }
    seadp_hdrlen = seadp_hdrlen - tlv_len;
    tlv_hdr = tlv_hdr + tlv_len;
  };

  MSS = (MTU - TOTAL_HEADER_SIZE);
  //fprintf(stderr, "MSS = %d\n", MSS);
  // payload
  payload_hdr = (char *)RTE_PTR_ADD(seadp_hdr_s, sizeof(SEADP_HDR));
  if (p + MSS >= size) {
     
      unsigned short payload = size - p;
      send_packet->pkt_len = TOTAL_HEADER_SIZE + payload;
      send_packet->data_len = send_packet->pkt_len;
      seadp_hdr_s->pflag =CFIN;
      ipv6_hdr_s->payload_len =
          rte_cpu_to_be_16(payload + SEADP_HDR_LEN + ID_HDR_LEN);
      rte_memcpy(payload_hdr, data + p, payload);
      seadp_hdr_s->checksum =
         fill_seadp_checksum(seadp_hdr_s, payload);
      //fprintf(stderr, "checksum = %d", seadp_hdr_s->checksum);
 


    return 0;
  } else {
    send_packet->pkt_len = TOTAL_HEADER_SIZE + MSS;
    send_packet->data_len = send_packet->pkt_len;
    seadp_hdr_s->pflag =DAT;
    ipv6_hdr_s->payload_len =
        rte_cpu_to_be_16(MSS + SEADP_HDR_LEN + ID_HDR_LEN);
    rte_memcpy(payload_hdr, data + p, MSS);
    seadp_hdr_s->checksum =
        fill_seadp_checksum(seadp_hdr_s, MSS);
    //fprintf(stderr, "checksum = %d", seadp_hdr_s->checksum);

    return (p + MSS);
  }
};
