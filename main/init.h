/*
 * Lorenzo Saino, Massimo Gallo
 *
 * Copyright (c) 2016 Alcatel-Lucent, Bell Labs
 *
 */

#ifndef _INIT_H_
#define _INIT_H_

/**
 * @file
 *
 * Initialization code
 */
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h> //pkt_fwd_loop
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>

#include "Defaults.h"
#include "cs_two.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 2048

/*
 * Define default  a send and recv ring for a worker core and write core, but
 only a one mempool is configured for each NUMA node
 */
#define WORKER_2_DISPATCH_RECV_RING_NAME "WORKER_2_D_RECV_RING_%u"
#define WORKER_2_TX_SEND_RING_NAME "WORKER_2_TX_SEND_RING_%u"
#define WRITE_2_WORKER_SEND_RING_NAME "WRITE_2_WORK_SEND_RING_%u"
#define WRITE_2_WORKER_RECV_RING_NAME "WRITE_2_WORK_RECV_RING_%u"
#define TX_2_WRITE_RECV_RING_NAME "TX_2_WRITE_REVE_RING_%u"
#define TX_2_WORKER_RECV_RING_NAME "TX_2_WORKER_RECV_RING_%u"
#define MB_2_DISPATCH_RECV_RING_NAME "MB_2_D_RECV_RING_%u"
#define MB_2_TX_SEND_RING_NAME "MB_2_TX_SEND_RING_%u"
#define WRITE_2_TX_1_EP_RING_NAME "EP_WRITE_2_TX_1_RING_%u"
#define WRITE_2_TX_2_EP_RING_NAME "EP_WRITE_2_TX_2_RING_%u"
#define MB_2_MC_RECV_RING_NAME "MB_2_MC_RING_%u"
#define MB_2_MC_SEND_RING_NAME "MB_2_MC_SEND_RING_%u"

#define SCHEDULE_MEMPOOL_NAME "SCHEDULE_MEMPOOL_%u_NAME"

#define WORKER_2_DISPATCH_RECV_RING_NAME_FLAG 1
#define WORKER_2_TX_SEND_RING_NAME_FLAG 2
#define WRITE_2_WORKER_SEND_RING_NAME_FLAG 3
#define WRITE_2_WORKER_RECV_RING_NAME_FLAG 4
#define TX_2_WRITE_RECV_RING_NAME_FLAG 5
#define TX_2_WORKER_RECV_RING_NAME_FLAG 6
#define MB_2_DISPATCH_RECV_RING_NAME_FLAG 7
#define MB_2_TX_SEND_RING_NAME_FLAG 8
#define WRITE_2_TX_1_EP_RING_NAME_FLAG 9
#define WRITE_2_TX_2_EP_RING_NAME_FLAG 10
#define MB_2_MC_RECV_RING_NAME_FLAG 11
#define MB_2_MC_SEND_RING_NAME_FLAG 12

#define SCHEDULE_MEMPOOL_NAME_FLAG 13

static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS, // Enable RSS
            .split_hdr_size = 0,
            .max_rx_pkt_len = ETHER_MAX_LEN, // set for Jumbo frame
            //.max_rx_pkt_len = 8192, // set for Jumbo frame
            //.header_split = 0,   /**< Header Split disabled */
            //.hw_ip_checksum = 1, /**< IP checksum offload disabled */
            //.hw_vlan_filter = 0, /**< VLAN filtering disabled */
            //.jumbo_frame = 0,    /**< Jumbo Frame Support disabled */
            //.hw_strip_crc = 0,   /**< CRC stripped by hardware */
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    //.rx_adv_conf = {
    //	.rss_conf = {
    //       .rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
    //	ETH_RSS_TCP | ETH_RSS_SCTP,  //RSS_HASH_FUNCTION
    //	},
    //},
};

// RX queues configuration, used later down in main
static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh =
        {
            .pthresh = RX_PTHRESH,
            .hthresh = RX_HTHRESH,
            .wthresh = RX_WTHRESH, // previous value is 4
        },
    .rx_free_thresh = 32,
};

// TX queues configuration, used later down in main
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh =
        {
            .pthresh = TX_PTHRESH, // previous value is 36
            .hthresh = TX_HTHRESH,
            .wthresh = TX_WTHRESH,
        },
    .tx_free_thresh = 32, /* Use PMD default values */
    .tx_rs_thresh = 32,   /* Use PMD default values */
    /*
     * As the example won't handle mult-segments and offload cases,
     * set the flag by default.
     */
    // Set to 0 for Jumbo frames
    //.txq_flags = 0, // ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

/** statistics collected by lcores for forwarding application */
struct stats
{
    uint32_t int_recv;     /**< number of Interest packets received */
    uint32_t int_dram_hit; /**< number of Interest packets served by CS DRAM */
    uint32_t int_ssd_hit;  /**< number of Interest packets served by CS  SSD */
    uint32_t int_no_hit;   /**< number of Interest packets that can not be served by
                          CS */

    uint64_t total_cpu_cycle; /**< count cpu cycle of one metric */
    uint64_t total_number;    /**< total pkt number of test        */

    uint32_t nb_chunk_write_to_ssd;  /**< number of segment that is written to SSD
                                      cache */
    uint32_t nb_chunk_read_from_ssd; /**< number of segment that is read from SSD
                                      cache */

    uint32_t data_recv; /**< number of Data received */
    uint32_t data_sent;
    uint32_t chunk_assembled;
    uint32_t nic_pkt_drop; /**< number of packet dropped in the NIC due to queue
                            overflow */
    uint32_t sw_pkt_drop;  /**< number of packet dropped by SW data strucutre
                            overflow */
    uint32_t malformed;    /**< number of malformed packets received */
} __attribute__((__packed__)) __rte_cache_aligned;

struct lcore_rx_queue
{
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct app_lcore_params
{
    /* packet buffers */
    struct rte_mempool *pktmbuf_pool;
    struct rte_mempool *tx_mbuf_pool;

    unsigned worker_id;
    struct rte_ring *recv_ring;
    struct rte_ring *send_ring;
    struct rte_mempool *shm_message_pool;

    /* ports */
    uint8_t nb_rx_ports;
    uint8_t nb_ports;
    struct lcore_rx_queue rx_queue[APP_MAX_ETH_PORTS]; // 10
    uint16_t tx_queue_id[APP_MAX_ETH_PORTS];           // 10

    /* stats */
    struct stats stats;

    /* data structures */
    cs_two_t *cs_two;
};

struct lcore_configuration_init
{
    uint8_t master;
    uint8_t dispatch;
    uint8_t tx_1;
    uint8_t tx_2;
    uint8_t mobile;
    uint8_t multicast;
    unsigned int worker[10];
    unsigned int writer[10]; //writer lcore id is 2 lower than worker lcore id
    uint8_t core_pairs; //number of pairs of worker-writer
};

struct app_global_config
{
    /*lcore configuration*/
    struct lcore_configuration_init lcore_configuration;

    /*file system space*/
    uint32_t fs_space;

    /*bucket num for a cs_two structure*/
    uint32_t bucket_num_for_cs_two;
  
    /* Packet burst settings */
    uint16_t tx_burst_size;
    uint16_t rx_burst_size;

    /* Packet pool settings */
    uint32_t nb_mbuf;
    uint32_t mbuf_size;
    uint32_t mempool_cache_size;

    /* Other config */
    uint8_t portmask;
    //uint8_t core_pairs;

    /* file system path */
    char *fs_path;

} __attribute__((__packed__)) __rte_cache_aligned;

// int
// init_mbuf_pools(struct app_global_config *app, struct app_lcore_params
// lcore[]);

// int
// init_ports( uint32_t portmask, uint8_t nb_rx_queues, uint8_t nb_tx_queues);

// void
// init_queues(uint32_t portmask, struct app_lcore_params lcore[]);

// void
// start_ports(uint32_t portmask, uint8_t promisc_mode);

/*
 * Get the queue name and mempool name
 */
char *get_rx_queue_name(unsigned id, unsigned flag);

void init_app(struct app_global_config *app, struct app_lcore_params lcore[]);
#endif /* _INIT_H_ */