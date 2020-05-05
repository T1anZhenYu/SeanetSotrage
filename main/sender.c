#include "sender.h"

//#define rte_pktmbuf_mtod(m, t) ((t)((char *)(m)->buf_addr + (m)->data_off))
//#define RTE_PTR_ADD(ptr, x) ((void *)((uintptr_t)(ptr) + (x)))
#include "dpdk_rcv.h"
#include "seaep_loop.h"
#include <rte_log.h>

#define rte_pktmbuf_mtod(m, t) ((t)((char *)(m)->buf_addr + (m)->data_off))

#define V4_HEADER_LEN 84
#define PAYLOAD_LEN 1250
#define reg_portid 1
#define IP_HDR_LEN 20
#define SEANET_HDR_LEN 44
#define SEADP_HDR_LEN 20

#ifndef SEADP_H

#define SEADP_H 1

#define SIP "fe80::46a8:42ff:fe0f:c37c"
#define CHUNK_TLEN 2097152

#endif

int check_link_status(uint16_t nb_ports) {
  struct rte_eth_link link;
  uint8_t port;

  for (port = 0; port < nb_ports; port++) {
    rte_eth_link_get(port, &link);

    if (link.link_status == 0) {
      printf("Port: %u Link DOWN\n", port);
      // return -1;
    }

    printf("Port: %u Link UP Speed %u\n", port, link.link_speed);
  }

  return 0;
}

unsigned short checksum(unsigned short *buffer, long size) {
  unsigned long cksum = 0;
  while (size > 1) {
    cksum += *buffer++;
    size -= sizeof(unsigned short);
  }
  if (size) {
    cksum += *(unsigned char *)buffer;
  }
  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);
  return (unsigned short)(~cksum);
  // if size if odd,auto fill 0x00
}

int Port_send_burst(struct mbuf_table *tx_mbuf, unsigned nb_pkts,
                    struct app_lcore_params *conf, uint8_t port,
                    uint16_t queue_id) {
  struct rte_mbuf **m_table;
  unsigned ret = 0;
  // struct ether_hdr *eth;
  // int i;

  m_table = tx_mbuf->m_table;
  port = 0;
  conf->stats.data_sent += ret;
  conf->stats.int_ssd_hit += nb_pkts;
  // printf("ret is %d\n", ret);
  // ret = check_link_status(2);
  // port_statistics[port].tx += ret;
  // printf("%d pkt sent\n", ret);
  uint16_t nb_tx = 0U;
  while (nb_tx < nb_pkts) {
    nb_tx += rte_eth_tx_burst(port, queue_id, m_table + nb_tx, nb_pkts - nb_tx);
  }
  return 0;
}

int send_packet(struct rte_mbuf *m, struct mbuf_table *tx_mbuf,
                struct app_lcore_params *conf, uint8_t port,
                uint16_t queue_id) {
  unsigned len;
  len = tx_mbuf->len;
  tx_mbuf->m_table[len] = m;
  len++;
  conf->stats.int_no_hit += 1;
  /* enough pkts to be sent */
  if (len == MAX_PKT_BURST) {
    // printf("send packet 2\n");
    conf->stats.data_sent += MAX_PKT_BURST;
    Port_send_burst(tx_mbuf, MAX_PKT_BURST, conf, port, queue_id);
    len = 0;
  }
  tx_bytes += m->data_len;

  tx_mbuf->len = len;
  return 0;
}

// unsigned char set_cflags(chunk){
// 	return 0;
// }

int chunk_sender_v2(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                    struct app_lcore_params *conf, uint16_t queue_id,
                    unsigned lcore_id) {
  struct rte_mempool *pool = conf->tx_mbuf_pool;
  struct rte_mbuf *in_pkt = &chunk->mbuf;
  const uint8_t *data = chunk->chunk;
  //rte_pktmbuf_free(in_pkt);
  //fprintf(stderr, "%s:%d chunk_sender_v2 skipped.\n", __FILE__, __LINE__);
  //return 0;

 //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
  int32_t chunk_size = chunk->chunk_size;
  int32_t seg_offset = chunk->offset;
  int32_t seg_size = chunk->size;
  int32_t seg_end = seg_offset + seg_size;
  
  int32_t offset = 0;
  for (;;) {
   // fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    struct rte_mbuf *out_pkt = rte_pktmbuf_alloc(pool);
  //  fprintf(stderr, "%s:%d %p\n", __FILE__, __LINE__, out_pkt);
    if (out_pkt == NULL) {
      continue;
	}
    
    offset = rcv_send(in_pkt, out_pkt, data, chunk_size, seg_offset, seg_size,
                      offset);
   // fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
    if (offset >= 0) {
  //    fprintf(stderr, "%s:%d %lld\n", __FILE__, __LINE__, offset);
      //rte_pktmbuf_free(out_pkt);
      send_packet(out_pkt, tx_mbuf, conf, 0, queue_id);
    }
    if (offset <= 0) {
    //  fprintf(stderr, "%s:%d breaking.\n", __FILE__, __LINE__);
      break;
    }
  }
  RTE_LOG(ERR, USER1, "Served: %s.\n", chunk->chunk_eid);
  return 0;
}

int chunk_sender(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                 struct app_lcore_params *conf, uint16_t queue_id,
                 unsigned lcore_id) {
  // struct send_param mysend_info;
  struct rte_mbuf *m;
  struct rte_mempool *shm_message_pool = NULL;
  m = &chunk->mbuf;

  shm_message_pool = lcore_conf[lcore_id].shm_message_pool;
  struct rte_mempool *pool = NULL;
  pool = conf->tx_mbuf_pool;

  // m = rte_pktmbuf_alloc(pool);
  int ret = -1;
  struct ether_hdr *eth, *eth_send;
  struct ipv6_hdr *ip, *ip_send;
  struct seanet_hdr *seanet, *seanet_send;
  struct seadp_hdr *seadp, *seadp_send;

  unsigned int offset;
  unsigned int data_len;
  unsigned int packet_number, i, pn;
  uint64_t *src_v6_ip = NULL;

  // LogWrite(DEBUG,"%s \n","Get chunk_msg_desc, begin to proccess!");
  /* pkt head parse */
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  ip = (struct ipv6_hdr *)RTE_PTR_ADD(eth, sizeof(struct ether_hdr));
  seanet = (struct seanet_hdr *)RTE_PTR_ADD(ip, sizeof(struct ipv6_hdr));
  seadp = (struct seadp_hdr *)RTE_PTR_ADD(seanet, sizeof(struct seanet_hdr));

  // mysend_info = chunk->send_info;

  /* swap mac */
  uint8_t temp_addr_bytes[6];
  for (i = 0; i < 6; i++) {
    temp_addr_bytes[i] = eth->d_addr.addr_bytes[i];
    eth->d_addr.addr_bytes[i] = eth->s_addr.addr_bytes[i];
    eth->s_addr.addr_bytes[i] = temp_addr_bytes[i];

    // printf("%x", eth->s_addr.addr_bytes[i]);
  }
  // printf("\n");
  eth->ether_type = htons(ETHER_TYPE_IPv6);
  /* IP head encapsulate */

  ip->vtc_flow = htonl(0x60000000);
  ip->payload_len = htons(ID_HEAD_LEN + SEADP_HEAD_LEN + PAYLOAD_LEN);
  ip->proto = SEANET_PROT;
  ip->hop_limits = 0xff;
  rte_memcpy(&ip->dst_addr, &ip->src_addr, 16);

  int j;
  src_v6_ip = (uint64_t *)malloc(16);
  j = inet_pton(AF_INET6, SIP, (void *)src_v6_ip);
  if (j > 0) {
    rte_memcpy(&ip->src_addr, src_v6_ip, 16);
  } else {
    printf("pton fail!\n");
  }

  /* SEANET head encapsulate */
  // seanet=(struct seanet_hdr*)(packet+sizeof(ipv4_hdr));
  seanet->id_next_head_type = SEADP_PROT;
  seanet->id_length = 44;
  seanet->id_seanet_prot_prop = htons(0x0009);

  // swap source eid and dst eid
  char temp[20] = {0};
  for (i = 0; i < 20; i++) {
    temp[i] = seanet->id_src_eid[i];
    seanet->id_src_eid[i] = seanet->id_dst_eid[i];
    seanet->id_dst_eid[i] = temp[i];
  }

  // LogWrite(DEBUG,"%s \n","Get chunk for EID:");
  // printf("\n");
  /* SEADP head encapsulate */

  // seadp->seadp_packet_type = 0x80; //DAT=1
  // seadp->seadp_tran_type_res = 0;
  seadp->seadp_packet_offset = htons(0);
  seadp->seadp_chunk_total_len = htonl(chunk->chunk_size);

  // swap src port and dst port
  uint16_t port_temp = seadp->seadp_src_port;
  seadp->seadp_src_port = seadp->seadp_dst_port;
  seadp->seadp_dst_port = port_temp;

  /* judge last segment */
  data_len = SIZE_OF_ONE_CHUNK;  // data_len = chunk->chunk_size
  offset = 0;
  packet_number = (data_len / PAYLOAD_LEN) + 1;

  // LogWrite(DEBUG,"%s %d \n","total packet number :", packet_number);
  // printf("total packet number : %d\n", packet_number);

  pn = 0;

  struct rte_mbuf *my_mbuf[packet_number];
  for (i = 0; i < packet_number; i++) {
    my_mbuf[i] = rte_pktmbuf_alloc(pool);
  }  // TODO：whether exists memory leak
  // printf("malloc finish\n");

  // ret = check_link_status(2);

  while (offset < data_len) {
    eth_send = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ip_send =
        (struct ipv6_hdr *)RTE_PTR_ADD(eth_send, sizeof(struct ether_hdr));
    seanet_send =
        (struct seanet_hdr *)RTE_PTR_ADD(ip_send, sizeof(struct ipv6_hdr));
    seadp_send =
        (struct seadp_hdr *)RTE_PTR_ADD(seanet_send, sizeof(struct seanet_hdr));

    // seadp_send->seadp_packet_type = seadp_send->seadp_packet_type | (0x80);
    // seadp_send->seadp_packet_offset = htonl(offset);
    // seadp_send->seadp_packet_order = htons(pn);

    /* write chunk_offset into payload according to */
    if (offset + PAYLOAD_LEN >= data_len) {  // LP
      // printf("last packet.\n");
      // seadp_send->seadp_tran_type_res = htons(0x1000); //LP

      unsigned short payload = data_len - offset;
      my_mbuf[pn]->pkt_len =
          ETH_HEAD_LEN + IPV6_HEAD_LEN + ID_HEAD_LEN + SEADP_HEAD_LEN + payload;
      my_mbuf[pn]->data_len = my_mbuf[pn]->pkt_len;
      // LogWrite(DEBUG,"%s %d \n","last segment length :", payload);
      // printf("payload(last segment length):%d\n", payload);

      /* write chunk_offset into payload, len:payload */

      rte_memcpy((char *)seadp_send + SEADP_HDR_LEN, (chunk->chunk) + offset,
                 payload);

      /* caculate checksum and set ip_len */
      seadp_send->seadp_packet_offset = htonl(offset);
      seadp_send->seadp_packet_order = htons(pn);
      // seadp_send->seadp_tran_type_res = seadp->seadp_tran_type_res | 0x08;
      seadp_send->seadp_checksum =
          checksum((unsigned short *)(seadp_send), SEADP_HEAD_LEN + payload);
      ip_send->payload_len = htons(ID_HEAD_LEN + SEADP_HEAD_LEN + payload);
      // printf("last ip len is %u\n", ip_send->payload_len);
      ret = 0;
    }

    else {
      my_mbuf[pn]->pkt_len = ETH_HEAD_LEN + IPV6_HEAD_LEN + ID_HEAD_LEN +
                             SEADP_HEAD_LEN + PAYLOAD_LEN;
      my_mbuf[pn]->data_len = my_mbuf[pn]->pkt_len;

      // memset(seadp_send + SEADP_HDR_LEN, 0, PAYLOAD_LEN);
      rte_memcpy((char *)seadp_send + SEADP_HDR_LEN, (chunk->chunk) + offset,
                 PAYLOAD_LEN);
      /* caculate checksum and set ip_len */
      seadp_send->seadp_checksum = checksum((unsigned short *)(seadp_send),
                                            SEADP_HEAD_LEN + PAYLOAD_LEN);
      seadp_send->seadp_packet_offset = htonl(offset);
      seadp_send->seadp_packet_order = htons(pn);
      ip_send->payload_len = htons(ID_HEAD_LEN + SEADP_HEAD_LEN + PAYLOAD_LEN);
    }
    // LogWrite(DEBUG,"%s %d %s %d \n","send offset :", offset, " #_#  packet
    // number :", pn);
    uint8_t port = 0;
    // rte_memcpy(my_mbuf[pn], m, sizeof(struct rte_mbuf));
    rte_memcpy(rte_pktmbuf_mtod(my_mbuf[pn], char *),
               rte_pktmbuf_mtod(m, char *), my_mbuf[pn]->pkt_len);
    ret = send_packet(my_mbuf[pn], tx_mbuf, conf, port, queue_id);

    offset += PAYLOAD_LEN;
    pn++;
  }

  if (pn != packet_number) {
    ret = -1;
    // LogWrite(DEBUG,"%s %d %s %d \n","packet number not enough, pn = ", pn,
    // "packet number = ", packet_number);
    printf("send number error, pn = %d \n", pn);
  }

  rte_mempool_put(shm_message_pool, chunk);
  return ret;
}

int send_expired(struct mbuf_table *tx_mbuf, uint8_t port,
                 struct app_lcore_params *conf, uint16_t queue_id) {
  unsigned len;
  len = tx_mbuf->len;
  if (len == 0) {
    printf("no packt to send\n");
    return -1;
  }
  // printf("send %dexpired packet\n", len);
  conf->stats.int_dram_hit += len;
  Port_send_burst(tx_mbuf, len, conf, port, queue_id);
  tx_mbuf->len = 0;
  return 0;
}

int register_sender_v2(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                       struct app_lcore_params *conf, uint16_t queue_id,
                       unsigned lcore_id) {
  struct register_desc *reg_msg;
  reg_msg = (struct register_desc *)(chunk->chunk);
  char eid[20];
  hex_string_2_char_array(eid, chunk->chunk_eid, 40);
  seaep_start_register(eid, NULL, reg_msg->delayParameter, reg_msg->ttl,
                       reg_msg->isGlobalVisable, NULL);
  return 0;
}

int register_sender(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                    struct app_lcore_params *conf, uint16_t queue_id,
                    unsigned lcore_id) {
  // printf("start!\n");
  // struct send_param mysend_info;
  struct rte_mbuf *m;
  struct rte_mempool *pool = NULL;
  struct rte_mempool *shm_message_pool = NULL;
  pool = conf->tx_mbuf_pool;

  shm_message_pool = lcore_conf[lcore_id].shm_message_pool;

  m = rte_pktmbuf_alloc(pool);
  int ret = -1;
  struct ether_hdr *eth;
  struct ipv6_hdr *ip;
  struct seanet_hdr *seanet;
  struct register_hdr *reginfo;
  struct register_desc *reg_msg;
  reg_msg = (struct register_desc *)(chunk->chunk);

  unsigned int i;
  uint64_t *src_v6_ip = NULL;

  /* pkt head parse */
  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  ip = (struct ipv6_hdr *)RTE_PTR_ADD(eth, sizeof(struct ether_hdr));
  seanet = (struct seanet_hdr *)RTE_PTR_ADD(ip, sizeof(struct ipv6_hdr));
  reginfo =
      (struct register_hdr *)RTE_PTR_ADD(seanet, sizeof(struct seanet_hdr));

  /* L2 head encapsulate */

  // printf("L2 encapsulate! \n");
  uint8_t d_addr_bytes[6];
  uint8_t s_addr_bytes[6];
  d_addr_bytes[0] = 0x52;
  d_addr_bytes[1] = 0x54;
  d_addr_bytes[2] = 0x00;
  d_addr_bytes[3] = 0x80;
  d_addr_bytes[4] = 0x2d;
  d_addr_bytes[5] = 0xcf;

  s_addr_bytes[0] = 0x90;
  s_addr_bytes[1] = 0xe2;
  s_addr_bytes[2] = 0xba;
  s_addr_bytes[3] = 0x86;
  s_addr_bytes[4] = 0x42;
  s_addr_bytes[5] = 0x3d;

  for (i = 0; i < 6; i++) {
    eth->d_addr.addr_bytes[i] = s_addr_bytes[i];
    // printf("%x", eth->d_addr.addr_bytes[i]);
  }
  for (i = 0; i < 6; i++) {
    eth->s_addr.addr_bytes[i] = d_addr_bytes[i];
    // printf("%x", eth->s_addr.addr_bytes[i]);
  }
  eth->ether_type = htons(ETHER_TYPE_IPv6);

  /* IP head encapsulate */

  // printf("L3 encapsulate! \n");
  ip->vtc_flow = htonl(0x60000000);
  ip->payload_len = htons(ID_HEAD_LEN + SEADP_HEAD_LEN + PAYLOAD_LEN);
  ip->proto = SEANET_PROT;
  ip->hop_limits = 0xff;
  rte_memcpy(&ip->dst_addr, &ip->src_addr, 16);

  int j;
  src_v6_ip = (uint64_t *)malloc(16);
  j = inet_pton(AF_INET6, SIP, (void *)src_v6_ip);
  if (j > 0) {
    rte_memcpy(&ip->src_addr, src_v6_ip, 16);
  } else {
    // printf("pton fail!\n");
  }

  /* SEANET head encapsulate */

  // printf("L4 encapsulate! \n");
  seanet->id_next_head_type = 0x66;
  seanet->id_length = 44;
  seanet->id_seanet_prot_prop = htons(0x09);
  // rte_memcpy(&seanet->id_src_eid, &reg->eid, 20);
  // rte_memcpy(&seanet->id_dst_eid, &reg->eid, 20);

  /* REGIST head encapsulate */
  // printf("L5 encapsulate! \n");

  reginfo->isGlobalVisable = htonl(reg_msg->isGlobalVisable);
  reginfo->connect_2_gnr_type = reg_msg->connect_2_gnr_type;
  reginfo->delayParameter = htonl(reg_msg->delayParameter);
  reginfo->ttl = reg_msg->ttl;
  char a[20];
  hex_string_2_char_array(a, chunk->chunk_eid, 40);
  memcpy(reginfo->eid, a, 20);
  printf("the global num is %d\n", reginfo->isGlobalVisable);
  printf("the connetct type is is %d\n", reginfo->connect_2_gnr_type);
  printf("the delay num is %d\n", reg_msg->delayParameter);
  printf("the ttl is %d\n", reginfo->ttl);

  // printf("Len encapsulate! \n");
  m->pkt_len = ETH_HEAD_LEN + IPV6_HEAD_LEN + ID_HEAD_LEN + REG_HEAD_LEN;
  m->data_len = m->pkt_len;
  ip->payload_len = htons(ID_HEAD_LEN + REG_HEAD_LEN);
  uint8_t port = 0;
  // printf("send regist request!");
  ret = send_packet(m, tx_mbuf, conf, port, queue_id);

  rte_mempool_put(shm_message_pool, chunk);

  return ret;
}

int send_mobile_msg(sendpacket *mb_packet, struct mbuf_table *tx_mbuf,
                    struct app_lcore_params *conf, uint16_t queue_id) {
  struct rte_mbuf *m;
  struct rte_mempool *pool = NULL;
  pool = conf->tx_mbuf_pool;
  int ret = -1;

  m = rte_pktmbuf_alloc(pool);
  if (m == NULL) {
    return -1;
  }
  m->pkt_len = mb_packet->len;
  m->data_len = m->pkt_len;
  memcpy(rte_pktmbuf_mtod(m, char *), mb_packet->packet, mb_packet->len);
  ///////
  printf("\nsend_mobile_msg len: %d\n data:\n", mb_packet->len);
  unsigned int i;
  for (i = 0; i < m->pkt_len; i++) printf("%x ", mb_packet->packet[i]);
  printf("\n");

  uint8_t port = 0;
  ret = send_packet(m, tx_mbuf, conf, port, queue_id);

  // rte_free(mb_packet);
  return ret;
}

int send_seaep_msg(sendpacket *mb_packet, struct mbuf_table *tx_mbuf,
                   struct app_lcore_params *conf, uint16_t queue_id) {
  struct rte_mbuf *m;
  struct rte_mempool *pool = NULL;
  pool = conf->tx_mbuf_pool;
  int ret = -1;

  m = rte_pktmbuf_alloc(pool);
  if (m == NULL) {
    return -1;
  }

  m->pkt_len = mb_packet->len;
  m->data_len = m->pkt_len;
  memcpy(rte_pktmbuf_mtod(m, char *), mb_packet->packet, mb_packet->len);
  ///////
  // printf("\nsend_seaep_msg len: %d\n data:\n", mb_packet->len);
  // unsigned int i;
  // for (i = 0; i < m->pkt_len; i++) printf("%x ", mb_packet->packet[i]);
  // printf("\n");

  uint8_t port = 0;
  ret = send_packet(m, tx_mbuf, conf, port, queue_id);

  //free(mb_packet->packet);
  //free(mb_packet);
  //rte_free(mb_packet);
  return ret;
}
