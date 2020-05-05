#ifndef _SENDER_H_
#define _SENDER_H_

#include "Defaults.h"
#include "seanet_packet.h"
#include "tx_action.h"

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
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include "util.h"

struct mbuf_table {
  unsigned len;
  struct rte_mbuf *m_table[MAX_PKT_BURST];
};

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];
extern volatile int64_t tx_bytes;

unsigned short checksum(unsigned short *, long);

int Port_send_burst(struct mbuf_table *, unsigned,
                    struct app_lcore_params *conf, uint8_t, uint16_t queue_id);
int send_packet(struct rte_mbuf *, struct mbuf_table *,
                struct app_lcore_params *conf, uint8_t, uint16_t queue_id);
int chunk_sender(struct chunk_msg_desc *, struct mbuf_table *,
                 struct app_lcore_params *, uint16_t queue_id,
                 unsigned lcore_id);
int chunk_sender_v2(struct chunk_msg_desc *, struct mbuf_table *,
                    struct app_lcore_params *, uint16_t queue_id,
                    unsigned lcore_id);
int check_link_status(uint16_t nb_ports);
int send_expired(struct mbuf_table *tx_mbuf, uint8_t port,
                 struct app_lcore_params *conf, uint16_t queue_id);
int register_sender(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                    struct app_lcore_params *conf, uint16_t queue_id,
                    unsigned lcore_id);
int register_sender_v2(struct chunk_msg_desc *chunk, struct mbuf_table *tx_mbuf,
                       struct app_lcore_params *conf, uint16_t queue_id,
                       unsigned lcore_id);
int send_mobile_msg(sendpacket *mb_packet, struct mbuf_table *tx_mbuf,
                    struct app_lcore_params *conf, uint16_t queue_id);
int send_seaep_msg(sendpacket *mb_packet, struct mbuf_table *tx_mbuf,
                   struct app_lcore_params *conf, uint16_t queue_id);
#endif /* _SENDER_H_ */
