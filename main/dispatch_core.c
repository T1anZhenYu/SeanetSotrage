#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_timer.h>

#include "dispatch_core.h"
#include "util.h"

#include <dirent.h>
#include <sys/stat.h>

//#define HOST_IPV6 "2400:dd01:1037:12:192:168:12:1"
#define HOST_IPV6 "7878:7878:7878:7878:7878:7878:7878:7878"

#define HOST_EID "1212121212121212121212121212121212121212"

volatile int64_t tx_bytes = 0;

#define DISPATCH_CORE_LOG(...) \
  RTE_LOG(DEBUG, USER1, "[DISPATCH CORE LOG]: " __VA_ARGS__)
#define DISPATCH_CORE_WARN(...) \
  RTE_LOG(WARNING, USER1, "[DISPATCH CORE WARN]: " __VA_ARGS__)

void dispatch_recovery_packet(char *eid, struct app_lcore_params *conf, struct app_global_config *app)
{
  unsigned worker_id_sequence, worker_id;
  struct ether_hdr *eth_hdr;
  char *ring_name;
  struct rte_ring *ring = NULL;
  struct rte_mempool *pool;
  struct rte_mbuf *m_packet;
  char eid_short_array[5];

  pool = conf->pktmbuf_pool;
  m_packet = rte_pktmbuf_alloc(pool);
  if (m_packet == NULL)
  {
    return;
  }

  strncpy(eid_short_array, eid + 36, 4);
  eid_short_array[4] = '\0';

  eth_hdr = rte_pktmbuf_mtod(m_packet, struct ether_hdr *);

  m_packet->ol_flags = TYPE_RECOVERY;

  // copy eid to mbuf
  rte_memcpy((char *)eth_hdr, eid, EID_LEN_HEX + 1);

  worker_id_sequence = (htoi(eid_short_array) % app->lcore_configuration.core_pairs);
  worker_id = app->lcore_configuration.worker[worker_id_sequence];
  RTE_LOG(DEBUG, EAL, "worker id is %u\n", worker_id);
  //printf("worker id is %d\n", worker_id);
  ring_name =
      get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
  ring = rte_ring_lookup(ring_name);
  //printf("ring name is %s \n", ring_name);
  if (ring == NULL)
  {
    rte_exit(EXIT_FAILURE,
             " core:problem getting recv ring, ring_name:%s\n",
             ring_name);
  }
  // printf("this packet have finish dispatch work! \n\n");
  if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
  {
    printf("!!!!!!!!!!\n");
    RTE_LOG(WARNING, EAL,
            "[DISPATCH]:Not enough room in the ring to enqueue on socket\n");
    conf->stats.sw_pkt_drop++;
    return;
  }
}

int64_t dispatch_packet(struct rte_mbuf *m_packet, struct app_global_config *app,
                        struct app_lcore_params *conf, unsigned lcore_id,
                        unsigned socket_id, uint8_t port_id)
{
  unsigned worker_id_sequence, worker_id;
  int64_t data_len = m_packet->data_len;
  struct ether_hdr *eth_hdr;
  struct ipv6_hdr *ipv6_hdr;
  struct seanet_hdr *id_hdr;
  struct udp_hdr *udp_hdr;
  struct seadp_hdr *seadp_hdr;

  char src_eid[EID_LEN_HEX + 1];
  char dst_eid[EID_LEN_HEX + 1];
  char *ring_name;
  struct rte_ring *ring = NULL;

  char src_eid_short_array[5];
  char dst_eid_short_array[5];

  eth_hdr = rte_pktmbuf_mtod(m_packet, struct ether_hdr *);

  DISPATCH_CORE_LOG(
      "LCORE_%u: Received packet "
      "from port %u. 0x%04x\n",
      lcore_id, port_id, eth_hdr->ether_type);
  if (eth_hdr->ether_type != ETHER_TYPE_IPv6_BE)
  {
    DISPATCH_CORE_LOG(
        "LCORE_%u: Received non-IPv6 packet "
        "from port %u. Dropping\n",
        lcore_id, port_id);

    // DISPATCH_CORE_LOG("the ether_type is %x \n",eth_hdr->ether_type);
    // DISPATCH_CORE_LOG("the ETHER_TYPE_IPv6 is %x \n",ETHER_TYPE_IPv6_BE);

    rte_pktmbuf_free(m_packet);
    conf->stats.malformed++;
    return data_len;
  }

  ipv6_hdr = (struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
  if (ipv6_hdr->proto == SEANET_PROT) //廉文瀚注释 跟据标志位确定seadp或udp   加一类（else if）
  {
    id_hdr =
        (struct seanet_hdr *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct ipv6_hdr));
    if (id_hdr->id_next_head_type != SEADP_PROT && id_hdr->id_next_head_type !=0x02)
    {
      DISPATCH_CORE_LOG(
          "LCORE_%u: Received SEANET packet, protocol is %u, but requiring is "
          "%u "
          "from port %u. Dropping\n",
          lcore_id, id_hdr->id_next_head_type, SEADP_PROT, port_id);

      rte_pktmbuf_free(m_packet);
      conf->stats.malformed++;
      return data_len;
    }
    if(id_hdr->id_next_head_type == 0x02)  //廉文瀚新增rawsocket情况
    {
      DISPATCH_CORE_LOG("Received Rawsocket packet!!!!\n\n\n\n");
      char_array_2_hex_string(src_eid, (unsigned char *)id_hdr->id_src_eid,
                              EID_LEN);
      src_eid[40] = '\0';
      DISPATCH_CORE_LOG("src_eid = %s\n", src_eid);
      strncpy(src_eid_short_array, src_eid + 36, 4);
      src_eid_short_array[4] = '\0';
      // DISPATCH_CORE_LOG("src_eid_short_array is %s\n",src_eid_short_array );

      char_array_2_hex_string(dst_eid, (unsigned char *)id_hdr->id_dst_eid,
                              EID_LEN);
      dst_eid[40] = '\0';
      DISPATCH_CORE_LOG("dst_eid = %s\n", dst_eid);
      strncpy(dst_eid_short_array, dst_eid + 36, 4);
      dst_eid_short_array[4] = '\0';

      
      {
        conf->stats.data_recv += 1;
        
         
        m_packet->ol_flags = TYPE_RAWSOCKET;
        
        
        worker_id_sequence = (htoi(dst_eid_short_array) % app->lcore_configuration.core_pairs);
        worker_id = app->lcore_configuration.worker[worker_id_sequence];

        RTE_LOG(DEBUG, EAL, "worker id is %d\n", worker_id);
        ring_name = get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
        ring = rte_ring_lookup(ring_name);
        if (ring == NULL)
        {
          rte_exit(EXIT_FAILURE,
                  " core:socket %u has problem getting recv ring, ring_name:%s, "
                  "lcore_id:%u \n",
                  socket_id, ring_name, lcore_id);
        }
        printf("this packet have finish dispatch work! \n\n");
        if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
        {
          RTE_LOG(
              WARNING, EAL,
              "[DISPATCH]:Not enough room in the ring to enqueue on socket:%u \n",
              socket_id);
          rte_pktmbuf_free(m_packet);
          conf->stats.sw_pkt_drop++;
          return data_len;
        }
      }

    }
    if(id_hdr->id_next_head_type == SEADP_PROT)
    {
      DISPATCH_CORE_LOG("Received SEANET packet!!!!\n");
      char_array_2_hex_string(src_eid, (unsigned char *)id_hdr->id_src_eid,
                              EID_LEN);
      src_eid[40] = '\0';
      DISPATCH_CORE_LOG("src_eid = %s\n", src_eid);
      strncpy(src_eid_short_array, src_eid + 36, 4);
      src_eid_short_array[4] = '\0';
      // DISPATCH_CORE_LOG("src_eid_short_array is %s\n",src_eid_short_array );

      char_array_2_hex_string(dst_eid, (unsigned char *)id_hdr->id_dst_eid,
                              EID_LEN);
      dst_eid[40] = '\0';
      DISPATCH_CORE_LOG("dst_eid = %s\n", dst_eid);
      strncpy(dst_eid_short_array, dst_eid + 36, 4);
      dst_eid_short_array[4] = '\0';
      // DISPATCH_CORE_LOG("dst_eid_short_array is %s\n", dst_eid_short_array);

      //   int i = 0;
      //   for (; i < id_hdr->id_length + sizeof(struct seadp_hdr); i++) {
      //     printf("%02x ", *(uint8_t *)((uintptr_t)(id_hdr) + (i)));
      //     if (i % 32 == 31) {
      //       printf("\n");
      //     } else if (i % 8 == 7) {
      //       printf(" ");
      //     }
      //}
      //   printf("\n");

      seadp_hdr =
          (struct seadp_hdr *)RTE_PTR_ADD(id_hdr, sizeof(struct seanet_hdr));

      uint16_t src_port = rte_be_to_cpu_16(seadp_hdr->seadp_src_port);
      uint16_t dst_port = rte_be_to_cpu_16(seadp_hdr->seadp_dst_port);
      uint8_t version = (seadp_hdr->version_n_type) >> 4;
      uint8_t type = (seadp_hdr->version_n_type) & 0x0f;
      uint8_t hdr_len = seadp_hdr->hdr_len;
      uint8_t cache_flag = seadp_hdr->seadp_cache_type;
      uint8_t storage_flag = seadp_hdr->storage_flag;
      uint16_t seq = rte_be_to_cpu_16(seadp_hdr->seadp_packet_order);
      uint16_t chksum = rte_be_to_cpu_16(seadp_hdr->seadp_checksum);
      uint32_t offset = rte_be_to_cpu_32(seadp_hdr->seadp_packet_offset);
      uint32_t chunk_len = rte_be_to_cpu_32(seadp_hdr->seadp_chunk_total_len);

      //DISPATCH_CORE_WARN("src_port = 0x%04x\n", src_port);
      //DISPATCH_CORE_WARN("dst_port = 0x%04x\n", dst_port);
      //DISPATCH_CORE_WARN("version = 0x%1x\n", version);
      //DISPATCH_CORE_WARN("pkt_type = 0x%1x\n", type);
      //DISPATCH_CORE_WARN("hdr_len = 0x%02x\n", hdr_len);
      //DISPATCH_CORE_WARN("cache_flag = 0x%02x\n", cache_flag);
      //DISPATCH_CORE_WARN("storage_flag = 0x%02x\n", storage_flag);
      //DISPATCH_CORE_WARN("seq = 0x%04x\n", seq);
      //DISPATCH_CORE_WARN("chksum = 0x%04x\n", chksum);
      //DISPATCH_CORE_WARN("offset = 0x%08x\n", offset);
      //DISPATCH_CORE_WARN("chunk_len = 0x%08x\n", chunk_len);

      if ((DATA_SIGN & type) == DATA_SIGN)
      {
        conf->stats.data_recv += 1;
        if(strcmp(dst_eid, HOST_EID) != 0)
        {
          //dst eid != host eid, which means that this data is pass-by
          m_packet->ol_flags = TYPE_DATA;
        }
        else
        {
          // give to seadp client
          m_packet->ol_flags = TYPE_SEADP_CLIENT;
        }
        
        worker_id_sequence = (htoi(dst_eid_short_array) % app->lcore_configuration.core_pairs);
        worker_id = app->lcore_configuration.worker[worker_id_sequence];

        RTE_LOG(DEBUG, EAL, "worker id is %d\n", worker_id);
        ring_name = get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
        ring = rte_ring_lookup(ring_name);
        if (ring == NULL)
        {
          rte_exit(EXIT_FAILURE,
                  " core:socket %u has problem getting recv ring, ring_name:%s, "
                  "lcore_id:%u \n",
                  socket_id, ring_name, lcore_id);
        }
        // printf("this packet have finish dispatch work! \n\n");
        if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
        {
          RTE_LOG(
              WARNING, EAL,
              "[DISPATCH]:Not enough room in the ring to enqueue on socket:%u \n",
              socket_id);
          rte_pktmbuf_free(m_packet);
          conf->stats.sw_pkt_drop++;
          return data_len;
        }
      }
      else if (type == REQ_SIGH)
      {
        m_packet->ol_flags = TYPE_REQ;
        //int jj = 0;
        //for(jj=0;jj<16;jj++){
        //  printf("the received request packet ipv6 addr network order is %x\n",ipv6_hdr->dst_addr[jj]);
        //}
        char host_ipv6_n[46];
        if (inet_ntop(AF_INET6, ipv6_hdr->dst_addr, host_ipv6_n, 46) == NULL)
        {
          //printf("inet_pton ipv6 addr wrong!\n");
        }
        //printf("the network order of src ip is %s\n", host_ipv6_n);
        //printf("the network order of our ip is %s\n", HOST_IPV6);
        if (strcmp(host_ipv6_n, HOST_IPV6) != 0)
        {
          DISPATCH_CORE_WARN(
              "we receive a request which does not belong to this host, we will "
              "ignore it!!!!\n");
          rte_pktmbuf_free(m_packet);
          return data_len;
        }
        //printf("we receive a request which  belongs to this host!!!!\n");
        worker_id_sequence = (htoi(dst_eid_short_array) % app->lcore_configuration.core_pairs);
        worker_id = app->lcore_configuration.worker[worker_id_sequence];
        printf("we calculate worker id is %u\n", worker_id);

        ring_name =
            get_rx_queue_name(worker_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);
        ring = rte_ring_lookup(ring_name);
        if (ring == NULL)
        {
          rte_exit(EXIT_FAILURE,
                  " core:socket %u has problem getting recv ring, ring_name:%s, "
                  "lcore_id:%u \n",
                  socket_id, ring_name, lcore_id);
        }
        // printf("the chunk request packet have finish dispatch work! \n\n");
        if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
        {
          DISPATCH_CORE_WARN(
              "not enough room in the ring to enqueue on socket:%u \n",
              socket_id);
          rte_pktmbuf_free(m_packet);
          conf->stats.sw_pkt_drop++;
          return data_len;
        }
      }
      else{
        printf("protocol is unknown:%u\n", type);
        rte_pktmbuf_free(m_packet);
        conf->stats.sw_pkt_drop++;
      }
    }
  }
  else if (ipv6_hdr->proto == UDP_PROT)
  {
    udp_hdr = (struct udp_hdr *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct ipv6_hdr));
    // printf("the mb event msg src port is %d\n", udp_hdr->src_port);
    // printf("the mb event msg dst port is %d\n", udp_hdr->dst_port);
    if ((ntohs(udp_hdr->src_port) == MOB_EVENT_SRC_PORT) &&
        (ntohs(udp_hdr->dst_port) == MOB_EVENT_DST_PORT))
    {
      m_packet->ol_flags = MOBILE_TYPE;
      ring_name =
          get_rx_queue_name(app_conf.lcore_configuration.mobile, MB_2_DISPATCH_RECV_RING_NAME_FLAG);
      ring = rte_ring_lookup(ring_name);
      if (ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 " core:socket %u has problem getting recv ring, ring_name:%s, "
                 "lcore_id:%u \n",
                 socket_id, ring_name, lcore_id);
      }
      // printf("the chunk request packet have finish dispatch work! \n\n");
      if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
      {
        DISPATCH_CORE_WARN(
            "Not enough room in the ring for dispatch to mb core to enqueue on "
            "socket:%u \n",
            socket_id);
        rte_pktmbuf_free(m_packet);
        conf->stats.sw_pkt_drop++;
        return data_len;
      }
    }
    else if ((ntohs(udp_hdr->src_port) == MULTICAST_SRC_PORT) &&
             (ntohs(udp_hdr->dst_port) == MULTICAST_DST_PORT))
    {
      m_packet->ol_flags = MULTICAST_TYPE;
      ring_name =
          get_rx_queue_name(app_conf.lcore_configuration.mobile, MB_2_DISPATCH_RECV_RING_NAME_FLAG);
      ring = rte_ring_lookup(ring_name);
      if (ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 " core:socket %u has problem getting recv ring, ring_name:%s, "
                 "lcore_id:%u \n",
                 socket_id, ring_name, lcore_id);
      }
      // printf("the chunk request packet have finish dispatch work! \n\n");
      if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
      {
        DISPATCH_CORE_WARN(
            "Not enough room in the ring for dispatch to mb core to enqueue on "
            "socket:%u \n",
            socket_id);
        rte_pktmbuf_free(m_packet);
        conf->stats.sw_pkt_drop++;
        return 0;
      }
    }
    else if ((ntohs(udp_hdr->dst_port) < RESOLUTION_REPLY_UDP_PORT_MAX) &&
             ntohs(udp_hdr->dst_port) >= RESOLUTION_REPLY_UDP_PORT_MIN)
    {
      m_packet->ol_flags = SEAEP_TYPE;
      ring_name =
          get_rx_queue_name(app_conf.lcore_configuration.mobile, MB_2_DISPATCH_RECV_RING_NAME_FLAG);
      ring = rte_ring_lookup(ring_name);
      if (ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 " core:socket %u has problem getting recv ring, ring_name:%s, "
                 "lcore_id:%u \n",
                 socket_id, ring_name, lcore_id);
      }
      printf("the chunk request packet have finish dispatch work! \n\n");
      if (rte_ring_enqueue(ring, (void *)m_packet) < 0)
      {
        DISPATCH_CORE_WARN(
            "Not enough room in the ring for dispatch to mb core to enqueue on "
            "socket:%u \n",
            socket_id);
        rte_pktmbuf_free(m_packet);
        conf->stats.sw_pkt_drop++;
        return 0;
      }
    }
    else
    {
      DISPATCH_CORE_LOG("unkown udp port, we do not process it!\n");
      rte_pktmbuf_free(m_packet);
      conf->stats.malformed++;
      return data_len;
    }
  }
  else
  {
    DISPATCH_CORE_LOG(
        "LCORE_%u: Received IPv6 packet, protocol is %u, but requiring is %u "
        "or %u "
        "from port %u. Dropping\n",
        lcore_id, ipv6_hdr->proto, SEANET_PROT, UDP_PROT, port_id);

    rte_pktmbuf_free(m_packet);
    conf->stats.malformed++;
    return data_len;
  }
  return data_len;
}

static int list_files(const char *path, struct app_lcore_params *conf, struct app_global_config *app)
{
  if (path == NULL)
  {
    RTE_LOG(CRIT, USER1, "NULL path given.\n", path);
    return 0;
  }
  struct dirent *de;
  DIR *dr = opendir(path);
  if (dr == NULL)
  {
    RTE_LOG(ERR, USER1, "Could not open directory <%s>.\n", path);
    return -1;
  }
  while ((de = readdir(dr)) != NULL)
  {
    char subpath[256];
    strncpy(subpath, path, sizeof(subpath));
    strncat(subpath, "/", sizeof(subpath));
    strncat(subpath, de->d_name, sizeof(subpath));
    struct stat statbuf;
    if (stat(subpath, &statbuf) == -1)
    {
      RTE_LOG(ERR, USER1, "Could not stat <%s> (%d:%s).\n", subpath,
              errno, strerror(errno));
      return -1;
    }
    if (S_ISREG(statbuf.st_mode))
    {
      RTE_LOG(DEBUG, USER1, "Regular file <%s/%s>.\n", subpath, de->d_name);
      dispatch_recovery_packet(de->d_name, conf, app);
    }
    else if (S_ISDIR(statbuf.st_mode))
    {
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
      {
        continue;
      }
      else
      {
        list_files(subpath, conf, app); // Ignore return value.
      }
    }
  }
  closedir(dr);
  return 0;
}

int dispatch_loop(__attribute__((unused)) void *arg)
{
  struct app_lcore_params *conf;
  unsigned lcore_id, socket_id;

  uint8_t port_id, queue_id;
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST]; // 32

  int i, j, nb_rx;

  lcore_id = rte_lcore_id();
  socket_id = rte_socket_id();

  /* Get core configuration */
  conf = &lcore_conf[lcore_id];
  uint64_t *host_ipv6_n = (uint64_t *)malloc(16);

  DISPATCH_CORE_LOG("\n");
  DISPATCH_CORE_LOG("dispatch work begin(%d)!\n", conf->nb_rx_ports);

  /* The core has no RX queues to listen from */
  if (conf->nb_rx_ports == 0)
  {
    RTE_LOG(CRIT, USER1, "[LCORE_%u] I have no RX queues to read from. I quit\n",
            lcore_id);
    return -1;
  }

  for (i = 0; i < conf->nb_rx_ports; i++)
  {
    port_id = conf->rx_queue[i].port_id;
    queue_id = conf->rx_queue[i].queue_id;
    DISPATCH_CORE_LOG("[LCORE_%u] Listening on (port_id=%u, queue_id=%u)\n",
                      lcore_id, port_id, queue_id);
  }

  // struct rte_mbuf *mymbuf;
  // struct rte_mempool *pool = NULL;

  // pool = conf->pktmbuf_pool;
  // mymbuf = rte_pktmbuf_alloc(pool);

  // chunk discovery test
  //char eid[41] = "1234567890123456789012345678901234567890";
  //dispatch_recovery_packet(eid, conf);

  list_files("/data", conf, &app_conf);

  uint64_t start = rte_get_tsc_cycles();
  int64_t rx_bytes = 0;
  while (1)
  {
    uint64_t now = rte_get_tsc_cycles();
    uint64_t diff = now - start;
    uint64_t _1s = rte_get_tsc_hz();
    if (diff > _1s)
    {
      double rxv = rx_bytes * 8.0 / 1000 / 1000 / 1000 / ((double)diff / _1s);
      double txv = tx_bytes * 8.0 / 1000 / 1000 / 1000 / ((double)diff / _1s);
      start = now;
      rx_bytes = 0;
      tx_bytes = 0; //
      RTE_LOG(CRIT, USER1, "RX: %.3fGbps; TX: %.3fGbps.\n", rxv, txv);
    }
    /* Read packet from RX queues */
    for (i = 0; i < conf->nb_rx_ports; i++)
    {
      port_id = conf->rx_queue[i].port_id;
      queue_id = conf->rx_queue[i].queue_id;

      nb_rx = rte_eth_rx_burst((uint8_t)port_id, queue_id, pkts_burst,
                               MAX_PKT_BURST);
      if (nb_rx == 0)
      {
        continue;
      }

      // rte_memcpy(mymbuf, *pkts_burst, sizeof(struct rte_mbuf));
      // int nb_tx = rte_eth_tx_burst((uint8_t) port_id, queue_id, &mymbuf,
      // nb_rx); DISPATCH_CORE_LOG("after sending, nb_tx is %d\n", nb_tx);

      // DISPATCH_CORE_LOG("nb_rx is %d, port id is %d, queue id is %d\n",
      // nb_rx, port_id, queue_id);

      // Prefetch each received packet and call forward function
      /* Prefetch the first PREFETCH_OFFSET packets */
      for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
      {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
        rte_prefetch0(
            rte_pktmbuf_mtod(pkts_burst[j] + RTE_CACHE_LINE_SIZE, void *));
      }
      /*
       * Prefetch each time 1 packet and forward 1 already prefetched
       * packet until there are no more packets to prefetch.
       *
       * This paced prefetching helps ensuring no cache thrashing happens.
       * In fact L1 cache has limited size (32KB on all most recent x86
       * architectures, e.g. Nehalem, Sandy Bridge, Haswell). Prefetching
       * more packets would certainly lead to thrashing.
       *
       * Maybe thrashing could be further reduced by prefetching fewer
       * packets in L1 and prefetch all other packets in L3, then do
       * 1-by-1 prefetching, but the availability of the packet in L3
       * before prefetching requires a smaller prefetch window.
       */

      for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++)
      {
        rte_prefetch0(
            rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *)); // 3
        rte_prefetch0(rte_pktmbuf_mtod(
            pkts_burst[j + PREFETCH_OFFSET] + RTE_CACHE_LINE_SIZE, void *));
        rx_bytes += dispatch_packet(pkts_burst[j], &app_conf, conf, lcore_id, socket_id, port_id);
      }

      /* After all packets have been prefetched, forward remaining (already
       * prefetched) packets */
      for (; j < nb_rx; j++)
      {
        rx_bytes +=
            dispatch_packet(pkts_burst[j], &app_conf, conf, lcore_id, socket_id, port_id);
      }
    }
  }
  return 0;
}
