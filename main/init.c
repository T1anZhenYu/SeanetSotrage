/*
 * Zeng Li, Li Yuanhang
 *
 *
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include "init.h"
#include "util.h"
#include "multicast_ae.h"

#define INIT_LOG(...) printf("[INIT]: " __VA_ARGS__)

uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

char *get_rx_queue_name(unsigned id, unsigned flag)
{
  /* buffer for return value. Size calculated by %u being replaced
   * by maximum 3 digits (plus an extra byte for safety) */
  static char
      worker_2_dispatch_recv_ring[sizeof(WORKER_2_DISPATCH_RECV_RING_NAME) + 2];
  static char worker_2_tx_send_ring[sizeof(WORKER_2_TX_SEND_RING_NAME) + 2];
  static char
      write_2_worker_send_ring[sizeof(WRITE_2_WORKER_SEND_RING_NAME) + 2];
  static char
      write_2_worker_recv_ring[sizeof(WRITE_2_WORKER_RECV_RING_NAME) + 2];
  static char tx_2_write_recv_ring[sizeof(TX_2_WRITE_RECV_RING_NAME) + 2];
  static char tx_2_worker_recv_ring[sizeof(TX_2_WORKER_RECV_RING_NAME) + 2];
  static char mb_2_dispatch_recv_ring[sizeof(MB_2_DISPATCH_RECV_RING_NAME) + 2];
  static char mb_2_tx_send_ring[sizeof(MB_2_TX_SEND_RING_NAME) + 2];
  static char write_2_tx_1_ep_send_ring[sizeof(WRITE_2_TX_1_EP_RING_NAME) + 2];
  static char write_2_tx_2_ep_recv_ring[sizeof(WRITE_2_TX_2_EP_RING_NAME) + 2];
  static char mb_2_mc_recv_ring[sizeof(MB_2_MC_RECV_RING_NAME) + 2];
  static char mb_2_mc_send_ring[sizeof(MB_2_MC_SEND_RING_NAME) + 2];

  static char buffer_mempool[sizeof(SCHEDULE_MEMPOOL_NAME) + 2];

  if (flag == WORKER_2_DISPATCH_RECV_RING_NAME_FLAG)
  {
    snprintf(worker_2_dispatch_recv_ring,
             sizeof(worker_2_dispatch_recv_ring) - 1,
             WORKER_2_DISPATCH_RECV_RING_NAME, id);
    return worker_2_dispatch_recv_ring;
  }
  else if (flag == WORKER_2_TX_SEND_RING_NAME_FLAG)
  {
    snprintf(worker_2_tx_send_ring, sizeof(worker_2_tx_send_ring) - 1,
             WORKER_2_TX_SEND_RING_NAME, id);
    return worker_2_tx_send_ring;
  }
  else if (flag == WRITE_2_WORKER_SEND_RING_NAME_FLAG)
  {
    snprintf(write_2_worker_send_ring, sizeof(write_2_worker_send_ring) - 1,
             WRITE_2_WORKER_SEND_RING_NAME, id);
    return write_2_worker_send_ring;
  }
  else if (flag == WRITE_2_WORKER_RECV_RING_NAME_FLAG)
  {
    snprintf(write_2_worker_recv_ring, sizeof(write_2_worker_recv_ring) - 1,
             WRITE_2_WORKER_RECV_RING_NAME, id);
    return write_2_worker_recv_ring;
  }
  else if (flag == TX_2_WRITE_RECV_RING_NAME_FLAG)
  {
    snprintf(tx_2_write_recv_ring, sizeof(tx_2_write_recv_ring) - 1,
             TX_2_WRITE_RECV_RING_NAME, id);
    return tx_2_write_recv_ring;
  }
  else if (flag == TX_2_WORKER_RECV_RING_NAME_FLAG)
  {
    snprintf(tx_2_worker_recv_ring, sizeof(tx_2_worker_recv_ring) - 1,
             TX_2_WORKER_RECV_RING_NAME, id);
    return tx_2_worker_recv_ring;
  }
  else if (flag == MB_2_DISPATCH_RECV_RING_NAME_FLAG)
  {
    snprintf(mb_2_dispatch_recv_ring, sizeof(mb_2_dispatch_recv_ring) - 1,
             MB_2_DISPATCH_RECV_RING_NAME, id);
    return mb_2_dispatch_recv_ring;
  }
  else if (flag == MB_2_TX_SEND_RING_NAME_FLAG)
  {
    snprintf(mb_2_tx_send_ring, sizeof(mb_2_tx_send_ring) - 1,
             MB_2_TX_SEND_RING_NAME, id);
    return mb_2_tx_send_ring;
  }
  else if (flag == SCHEDULE_MEMPOOL_NAME_FLAG)
  {
    snprintf(buffer_mempool, sizeof(buffer_mempool) - 1, SCHEDULE_MEMPOOL_NAME,
             id);
    return buffer_mempool;
  }
  else if (flag == WRITE_2_TX_1_EP_RING_NAME_FLAG)
  {
    snprintf(write_2_tx_1_ep_send_ring, sizeof(write_2_tx_1_ep_send_ring) - 1,
             WRITE_2_TX_1_EP_RING_NAME, id);
    return write_2_tx_1_ep_send_ring;
  }
  else if (flag == MB_2_MC_RECV_RING_NAME_FLAG)
  {
    snprintf(mb_2_mc_recv_ring, sizeof(mb_2_mc_recv_ring) - 1,
             MB_2_MC_RECV_RING_NAME, id);
    return mb_2_mc_recv_ring;
  }
  else if (flag == MB_2_MC_SEND_RING_NAME_FLAG)
  {
    snprintf(mb_2_mc_send_ring, sizeof(mb_2_mc_send_ring) - 1,
             MB_2_MC_SEND_RING_NAME, id);
    return mb_2_mc_send_ring;
  }

  else
  {
    return NULL;
  }

  // This code can not be reached
  return NULL;
}

static int init_mbuf_pools(struct app_global_config *app,
                           struct app_lcore_params lcore[])
{
  int socket_id;
  unsigned lcore_id;
  char pool_name[64];
  struct rte_mempool *pool[APP_MAX_SOCKETS];
  struct rte_mempool *tx_pool[APP_MAX_SOCKETS];

  /* This loop is needed */
  for (socket_id = 0; socket_id < APP_MAX_SOCKETS; socket_id++)
  {
    pool[socket_id] = NULL;
    tx_pool[socket_id] = NULL;
  }
  for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++)
  {
    lcore[lcore_id].pktmbuf_pool = NULL;
    lcore[lcore_id].tx_mbuf_pool = NULL;

    if (!rte_lcore_is_enabled(lcore_id))
    {
      continue;
    }
    socket_id = rte_lcore_to_socket_id(lcore_id);
    if (socket_id >= APP_MAX_SOCKETS)
    {
      rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
               socket_id, lcore_id, APP_MAX_SOCKETS);
    }

    if (pool[socket_id] == NULL)
    {
      snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%d", socket_id);
      pool[socket_id] = rte_mempool_create(
          pool_name,                               // Name
          app->nb_mbuf,                            // Number of elements 32765
          app->mbuf_size,                          // Size of each element
          app->mempool_cache_size,                 // Per-lcore cache size
          sizeof(struct rte_pktmbuf_pool_private), // private data size
          rte_pktmbuf_pool_init, NULL,             // pointer to func init mempool	and args
          rte_pktmbuf_init, NULL,                  // pointer to func init mbuf and args
          socket_id,                               // socket ID
          0);                                      // flags

      if (pool[socket_id] == NULL)
      {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d, err=-%d \n",
                 socket_id, rte_errno);
      }
      else
      {
        INIT_LOG("Allocated mbuf pool on socket %d\n", socket_id);
      }
    }
    lcore[lcore_id].pktmbuf_pool = pool[socket_id];

    if (tx_pool[socket_id] == NULL)
    {
      snprintf(pool_name, sizeof(pool_name), "tx_mbuf_pool_%d", socket_id);
      tx_pool[socket_id] = rte_mempool_create(
          pool_name,                               // Name
          8192,                                    // Number of elements 32765
          app->mbuf_size,                          // Size of each element
          app->mempool_cache_size,                 // Per-lcore cache size
          sizeof(struct rte_pktmbuf_pool_private), // private data size
          rte_pktmbuf_pool_init, NULL,             // pointer to func init mempool	and args
          rte_pktmbuf_init, NULL,                  // pointer to func init mbuf and args
          socket_id,                               // socket ID
          0);                                      // flags

      if (tx_pool[socket_id] == NULL)
      {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d, err=-%d \n",
                 socket_id, rte_errno);
      }
      else
      {
        INIT_LOG("Allocated tx mbuf pool on socket %d\n", socket_id);
      }
    }
    lcore[lcore_id].tx_mbuf_pool = tx_pool[socket_id];
  }
  return 0;
}

/**
 * @param portmask
 *   The mask of enabled ports passed via command line
 * @param nb_rx_queues
 *   The number of RX queues enabled in each port
 * @param nb_tx_queues
 *   The number of TX queues enabled in each port
 *
 */
static int init_ports(uint32_t portmask, uint8_t nb_rx_queues,
                      uint8_t nb_tx_queues)
{
  int ret;
  uint8_t port_id, nb_ports, nb_ports_available;
  /*
   * This data structure is used to retrieve properties from NICs, such max
   * nb of rx and tx queues, offload capabilities and Jumbo frames support.
   */
  struct rte_eth_dev_info dev_info;

  /*
   * Get the number of Ethernet devices initialized. Depends on the EAL
   * arguments specified when launching the program (Ethernet device
   * white/black-listing) and devices actually available in the machine and
   * attached to the DPDK driver.
   *
   * From now on, all devices whose port identifier is in the range
   * [0,  rte_eth_dev_count() - 1] can be operated on by network applications
   */
  nb_ports = rte_eth_dev_count();
  if (nb_ports == 0)
  {
    rte_exit(EXIT_FAILURE,
             "No Ethernet ports available. "
             "Did you attach the NICs to the DPDK driver?\n");
  }
  else if (nb_ports == 1)
  {
    INIT_LOG("Only one Ethernet port available to DPDK on this machine\n");
  }
  else if (nb_ports > APP_MAX_ETH_PORTS)
  {
    nb_ports = APP_MAX_ETH_PORTS;
  }
  INIT_LOG("Recognized %u ports on this machine.\n", nb_ports);

  nb_ports_available = nb_ports;

  /*
   * Initialize each port
   */
  for (port_id = 0; port_id < nb_ports; port_id++)
  {
    /*
     * Skip ports that are not enabled, i.e. that are not included in the
     * portmask provided by the user at launch time
     */
    if ((portmask & (1 << port_id)) == 0)
    {
      INIT_LOG("Skipping disabled port %u\n", port_id);
      nb_ports_available--;
      continue;
    }

    /*
     * I must have a dedicated hardware RX and TX queue per logical core to
     * operate correctly. These queues cannot be shared by cores without
     * using locks, which detriment performance
     */
    rte_eth_dev_info_get(port_id, &dev_info);
    if (nb_rx_queues > dev_info.max_rx_queues)
    {
      rte_exit(EXIT_FAILURE, "NIC %s has only %u hardware RX queues",
               dev_info.driver_name, dev_info.max_rx_queues);
    }
    if (nb_tx_queues > dev_info.max_tx_queues)
    {
      rte_exit(EXIT_FAILURE, "NIC %s has only %u hardware TX queues",
               dev_info.driver_name, dev_info.max_tx_queues);
    }
    /*
     * Make sure that the NIC supports Jumbo frames
     *
     */
    if (dev_info.max_rx_pktlen < 8192)
    {
      rte_exit(EXIT_FAILURE, "NIC %s does not support Jumbo frames",
               dev_info.driver_name);
    }
    /*
     * Configure a single port by specifying how many TX and RX
     * hardware queues have to be used in a device. Each RX and TX queue
     * can be identified with an integer from 0 to N-1.
     *
     * Note that in this specific case I enable as many RX and TX queues
     * as the number of lcores.
     *
     * This is not sufficient to init the RX and TX queues. I later need
     * to set up rx/tx queues with calls to rte_eth_rx_queue_setup
     * and rte_eth_tx_queue_setup
     *
     * The port_conf variable contains low-level configuration for the
     * NIC such as RSS configuration, checksum calculation offload,
     * VLAN and JumboFrame support. It is defined further up in this file
     */
    ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues,
                                &port_conf_default);
    if (ret < 0)
    {
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               port_id);
    }
    INIT_LOG("Initialized port %u with %u rx queues and %u tx queues\n",
             port_id, nb_rx_queues, nb_tx_queues);
  }
  if (!nb_ports_available)
  {
    rte_exit(EXIT_FAILURE,
             "All available ports are disabled. "
             "Please set portmask.\n");
  }
  return 0;
}

/* init d2worker worker2write write2worker worker2seaep write2seaep
Notice, mempool is only created on each NUMA socket
Notice, d2worker use the mbuf mempool,rather than schedule mempool
*/
static int init_shm_rings(struct app_global_config *app, struct app_lcore_params lcore[])
{
  unsigned flags = 0;
  unsigned socket_id;
  unsigned lcore_id;
  char *core_send_ring_name, *core_recv_ring_name;
  char *mempool_name;
  struct rte_mempool *message_pool[APP_MAX_SOCKETS]; // 2
  int iter = 0;

  /*Set it to null in case */
  for (socket_id = 0; socket_id < APP_MAX_SOCKETS; socket_id++)
  {
    message_pool[socket_id] = NULL;
  }

  /* Create ring and mempool, and bind it to each lcore */
  for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++)
  {
    // skip master core, dispatch core
    if (!rte_lcore_is_enabled(lcore_id) || lcore_id == app->lcore_configuration.master)
    {
      continue;
    }

    lcore[lcore_id].shm_message_pool = NULL;
    lcore[lcore_id].send_ring = NULL;
    lcore[lcore_id].recv_ring = NULL;

    socket_id = rte_lcore_to_socket_id(lcore_id);
    if (socket_id >= APP_MAX_SOCKETS)
    {
      rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
               socket_id, lcore_id, APP_MAX_SOCKETS);
    }

    /*Create and bind mempool for send and recv ring */
    mempool_name = get_rx_queue_name(socket_id, SCHEDULE_MEMPOOL_NAME_FLAG);
    if (message_pool[socket_id] == NULL)
    {
      message_pool[socket_id] = rte_mempool_create(
          mempool_name,
          SCHEDULE_MEMPOOL_SIZE,         // Number of elements 8192
          SCHEDULE_MEMPOOL_ELEMENT_SIZE, // Size of each element
          SCHEDULE_MEMPOOL_CACHE_SIZE,   // Per-lcore cache size 256
          0,                             // private data size
          NULL, NULL,                    // pointer to func init mempool and args
          NULL, NULL,                    // pointer to func init mbuf and args
          socket_id,                     // socket ID
          flags);                        // flags
      if (message_pool[socket_id] == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 "Cannot init memory pool used for communication for fwd and "
                 "ssd core on socket %d\n",
                 socket_id);
      }
    }

    lcore[lcore_id].shm_message_pool = message_pool[socket_id];
    if (lcore[lcore_id].shm_message_pool == NULL)
    {
      printf("the message pool is NULL,init fail! lcore id is %d\n", lcore_id);
    }

    // dispatch lcore, create ring for writer to tx to load seaep msg
    if (lcore_id == app->lcore_configuration.dispatch)
    {
      core_send_ring_name =
          get_rx_queue_name(app->lcore_configuration.tx_1, WRITE_2_TX_1_EP_RING_NAME_FLAG);
      core_recv_ring_name =
          get_rx_queue_name(app->lcore_configuration.tx_2, WRITE_2_TX_2_EP_RING_NAME_FLAG);

      // flags 0 means that mutiple producer and consumer. One producer and one
      // consumer
      lcore[lcore_id].send_ring =
          rte_ring_create(core_send_ring_name,
                          RING_WRITE_2_TX_EP_SIZE, // The size of the ring 1024
                          socket_id, flags);
      lcore[lcore_id].recv_ring =
          rte_ring_create(core_recv_ring_name,
                          RING_WRITE_2_TX_EP_SIZE, // 1024
                          socket_id, flags);
      // Check if we allocate success
      if (lcore[lcore_id].send_ring == NULL ||
          lcore[lcore_id].recv_ring == NULL)
      {
        printf(
            "Cannot init ring used for communication for writer and TX core in "
            "dispatch lcore_id:%u \n",
            lcore_id);
        rte_exit(EXIT_FAILURE,
                 "Cannot init ring used for communication for writer and TX "
                 "core in dispatch lcore_id:%u \n",
                 lcore_id);
      }
      else
      {
        INIT_LOG(
            "Allocated ring used for communication for writer and TX core in "
            "dispatch lcore_id:%u \n",
            lcore_id);
        //continue;
      }
    }

    // worker lcore
    for(iter = 0; iter < app->lcore_configuration.core_pairs; iter++)
    {
      if (lcore_id == app->lcore_configuration.worker[iter])
      {
        core_send_ring_name =
            get_rx_queue_name(lcore_id, WORKER_2_TX_SEND_RING_NAME_FLAG);
        core_recv_ring_name =
            get_rx_queue_name(lcore_id, WORKER_2_DISPATCH_RECV_RING_NAME_FLAG);

        //printf("the name of the worker ring is %s",core_send_ring_name);
        // flags 0 means that mutiple producer and consumer. One producer and one
        // consumer
        lcore[lcore_id].send_ring = rte_ring_create(
            core_send_ring_name,
            RING_CHUNK_NOTIFY_SHEDULE_SIZE, // The size of the ring 1024
            socket_id, flags);
        lcore[lcore_id].recv_ring = rte_ring_create(
            core_recv_ring_name,
            RING_DISPATCH_2_WORKER_SIZE, // The size of the dispatch to worker
                                         // ring 8192
            socket_id, flags);

        // Check if we allocate success
        if (lcore[lcore_id].send_ring == NULL ||
            lcore[lcore_id].recv_ring == NULL)
        {
          printf(
              "Cannot init ring used for communication for worker and "
              "dispatch/TX core for worker lcore_id:%u \n",
              lcore_id);
          rte_exit(EXIT_FAILURE,
                   "Cannot init ring used for communication for worker and "
                   "dispatch/TX core for worker lcore_id:%u \n",
                   lcore_id);
        }
        else
        {
          INIT_LOG(
              "Allocated ring used for communication for worker and dispatch/TX "
              "core for worker lcore_id:%u \n",
              lcore_id);
          //printf("worker send ring is %s\n", lcore[lcore_id].send_ring->name);
          //printf("worker receive ring is %s\n", lcore[lcore_id].recv_ring->name);
        }
        break;
      }
    }

    if (lcore_id == app->lcore_configuration.mobile)
    {
      core_recv_ring_name =
          get_rx_queue_name(lcore_id, MB_2_DISPATCH_RECV_RING_NAME_FLAG);
      core_send_ring_name =
          get_rx_queue_name(lcore_id, MB_2_TX_SEND_RING_NAME_FLAG);

      // flags 0 means that mutiple producer and consumer. One producer and one
      // consumer
      lcore[lcore_id].recv_ring =
          rte_ring_create(core_recv_ring_name,
                          RING_MB_2_DISPATCH_SIZE, // The size of the ring 2048
                          socket_id, flags);

      lcore[lcore_id].send_ring =
          rte_ring_create(core_send_ring_name,
                          RING_MB_2_TX_SIZE, // The size of the ring 1024
                          socket_id, flags);

      if (lcore[lcore_id].send_ring == NULL ||
          lcore[lcore_id].recv_ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 "Cannot init ring used for communication for mb and "
                 "tx/dispatch core for tx lcore_id:%u \n",
                 lcore_id);
      }
      else
      {
        INIT_LOG(
            "Allocated ring used for communication for mb and tx/dispatch core "
            "for tx lcore_id:%u \n",
            lcore_id);
      }
    }

    if (lcore_id == app->lcore_configuration.multicast)
    {
      core_recv_ring_name =
          get_rx_queue_name(lcore_id, MB_2_MC_RECV_RING_NAME_FLAG);
      core_send_ring_name =
          get_rx_queue_name(lcore_id, MB_2_MC_SEND_RING_NAME_FLAG);

      lcore[lcore_id].recv_ring =
          rte_ring_create(core_recv_ring_name,
                          RING_MB_2_MC_SIZE, // The size of the ring 1024
                          socket_id,
                          flags);
      lcore[lcore_id].send_ring =
          rte_ring_create(core_send_ring_name,
                          //RING_MB_2_MC_SIZE, // The size of the ring 1024
                          512,
                          socket_id,
                          flags);
      if (lcore[lcore_id].recv_ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 "Cannot init recv ring used for communication for mb and "
                 "mc core for lcore_id:%u \n",
                 lcore_id);
      }
      else if (lcore[lcore_id].send_ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 "Cannot init send ring used for communication for mb and "
                 "mc core for  lcore_id:%u \n",
                 lcore_id);
      }
      else
      {
        INIT_LOG(
            "Allocated ring used for communication for mb and mc core "
            "for mc lcore_id:%u \n",
            lcore_id);
      }
    }

    if (lcore_id == app->lcore_configuration.tx_1 || lcore_id == app->lcore_configuration.tx_2)
    {
      core_send_ring_name =
          get_rx_queue_name(lcore_id, TX_2_WRITE_RECV_RING_NAME_FLAG);
      core_recv_ring_name =
          get_rx_queue_name(lcore_id, TX_2_WORKER_RECV_RING_NAME_FLAG);

      // flags 0 means that mutiple producer and consumer. One producer and one
      // consumer
      lcore[lcore_id].send_ring = rte_ring_create(
          core_send_ring_name,
          RING_CHUNK_WRITE_2_TX_SIZE, // The size of the ring 1024
          socket_id, flags);

      lcore[lcore_id].recv_ring = rte_ring_create(
          core_recv_ring_name,
          RING_CHUNK_NOTIFY_SHEDULE_SIZE, // The size of the ring 1024
          socket_id, flags);
      // Check if we allocate success
      if (lcore[lcore_id].send_ring == NULL ||
          lcore[lcore_id].recv_ring == NULL)
      {
        rte_exit(EXIT_FAILURE,
                 "Cannot init ring used for communication for tx and "
                 "worker/write core for tx lcore_id:%u \n",
                 lcore_id);
      }
      else
      {
        INIT_LOG(
            "Allocated ring used for communication for tx and worker/write "
            "core for tx lcore_id:%u \n",
            lcore_id);
      }
    }

    //writer
    for(iter = 0; iter < app->lcore_configuration.core_pairs; iter++)
    {
      if (lcore_id == app->lcore_configuration.writer[iter])
      {
        core_send_ring_name =
            get_rx_queue_name(lcore_id, WRITE_2_WORKER_SEND_RING_NAME_FLAG);
        core_recv_ring_name =
            get_rx_queue_name(lcore_id, WRITE_2_WORKER_RECV_RING_NAME_FLAG);
        //printf("the name of the writer ring is %s",core_send_ring_name);
        // flags 0 means that mutiple producer and consumer. One producer and one
        // consumer
        lcore[lcore_id].send_ring = rte_ring_create(
            core_send_ring_name,
            RING_CHUNK_NOTIFY_SHEDULE_SIZE, // The size of the ring 1024
            socket_id, flags);

        lcore[lcore_id].recv_ring =
            rte_ring_create(core_recv_ring_name, RING_CHUNK_WORKER_2_WRITE_SIZE,
                            socket_id, flags);
        // Check if we allocate success
        if (lcore[lcore_id].send_ring == NULL ||
            lcore[lcore_id].recv_ring == NULL)
        {
          rte_exit(EXIT_FAILURE,
                  "Cannot init ring used for communication for write and worker "
                  "core for write lcore_id:%u \n",
                  lcore_id);
        }
        else
        {
          INIT_LOG(
              "Allocated ring used for communication for write and worker core "
              "for write lcore_id:%u \n",
              lcore_id);
        }
        break;
      }
    }
  }
  // If init failed, this function will exit directly. So the return value may
  // not have meaning
  return 0;
}

/**
 * Init all RX and TX queues
 *
 * @params portmask
 *   User-provided port mask
 */
static void init_queues(struct app_global_config *app, struct app_lcore_params lcore[])
{
  // Iterate over cores and ports to enable HW queues and map them to cores

  int ret;
  /*
   * queue_id is needed to keep track of the queue IDs assigned to each
   * lcore because there can be holes in the sequence of lcore IDs
   * (e.g. 1, 2, 4) but there cannot be holes in the RX and TX queues
   * lists.
   */
  uint8_t port_id, queue_id;
  uint8_t socket_id, lcore_id;
  uint8_t nb_ports;
  uint8_t nb_ports_available;

  /* Get number of ports enabled via command line */
  nb_ports = rte_eth_dev_count();
  nb_ports_available = get_nb_ports_available(app->portmask);
  for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++)
  {
    /* //skip control core, ssd io core */
    if (!rte_lcore_is_enabled(lcore_id))
    {
      continue;
    }

    socket_id = (uint8_t)rte_lcore_to_socket_id(lcore_id);

    if (lcore_id == app->lcore_configuration.dispatch)
    {
      lcore[lcore_id].nb_rx_ports = nb_ports_available;
      lcore[lcore_id].nb_ports = nb_ports;

      queue_id = 0;
      for (port_id = 0; port_id < nb_ports; port_id++)
      {
        /* Skip queue initialization for disabled ports */
        if ((app->portmask & (1 << port_id)) == 0)
        {
          continue;
        }

        lcore[lcore_id].rx_queue[port_id].port_id = port_id;
        lcore[lcore_id].rx_queue[port_id].queue_id = queue_id;

        // TODO: Review rx_conf, nv_rxd
        ret = rte_eth_rx_queue_setup(port_id, (uint16_t)queue_id, nb_rxd,
                                     socket_id, &rx_conf,
                                     lcore[lcore_id].pktmbuf_pool);
        if (ret < 0)
        {
          printf("rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
                 (unsigned)port_id);
          rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                   ret, (unsigned)port_id);
        }
      }
    }
    if (lcore_id == app->lcore_configuration.tx_1)
    {
      queue_id = 0;
      for (port_id = 0; port_id < nb_ports; port_id++)
      {
        /* Skip queue initialization for disabled ports */
        if ((app->portmask & (1 << port_id)) == 0)
        {
          continue;
        }
        /* init one TX queue on each port
         *
         * TODO: If all lcores write on the same queue_id for each port,
         * then a scalar value is fine. This structure allows more
         * flexibility. See whether I should improve the situation at some
         * point
         */
        lcore[lcore_id].tx_queue_id[port_id] = queue_id;
        ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id,
                                     &tx_conf);
        if (ret < 0)
        {
          printf("rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
                 (unsigned)port_id);
          rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                   ret, (unsigned)port_id);
        }
      }
    }
    if (lcore_id == app->lcore_configuration.tx_2)
    {
      queue_id = 1;
      for (port_id = 0; port_id < nb_ports; port_id++)
      {
        /* Skip queue initialization for disabled ports */
        if ((app->portmask & (1 << port_id)) == 0)
        {
          continue;
        }
        /* init one TX queue on each port
         **
         ** TODO: If all lcores write on the same queue_id for each port,
         ** then a scalar value is fine. This structure allows more
         ** flexibility. See whether I should improve the situation at some
         ** point
         **/
        lcore[lcore_id].tx_queue_id[port_id] = queue_id;
        ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id,
                                     &tx_conf);
        if (ret < 0)
        {
          printf("rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
                 (unsigned)port_id);
          rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                   ret, (unsigned)port_id);
        }
      }
    }
  }
}

static void init_storage_data_structures(struct app_global_config *app, struct app_lcore_params lcore[])
{
  uint8_t lcore_id, socket_id;
  int iter = 0;

  for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++)
  {
    /* skip master core, writer core, tx core  */
    //if ((!rte_lcore_is_enabled(lcore_id)) ||
    if ((!rte_lcore_is_enabled(lcore_id)) || lcore_id == app->lcore_configuration.master ||
        lcore_id == app->lcore_configuration.tx_1 ||
        lcore_id == app->lcore_configuration.tx_2 ||
        lcore_id == app->lcore_configuration.multicast ||
        lcore_id == app->lcore_configuration.mobile)
    {
      continue;
    }

    socket_id = rte_lcore_to_socket_id(lcore_id);

    for(iter = 0; iter < app->lcore_configuration.core_pairs; iter ++)
    {
      if (lcore_id == app->lcore_configuration.writer[iter])
      {

        lcore[lcore_id].cs_two =
            cs_two_create_for_write(DRAM_LRU_QUEUE_SIZE_WRITE_CORE, socket_id);
        break;
        //TODO: the size of lru change with the pair num;
      }
      else if (lcore_id == app->lcore_configuration.worker[iter])
      {
        //  70.8W, 1280
        lcore[lcore_id].cs_two = cs_two_create(
            app->bucket_num_for_cs_two, DRAM_LRU_QUEUE_SIZE_WORKER_CORE, socket_id);
        break;
        //TODO: the size of lru change with the pair num;
      }
    }
  }
}

static void start_ports(uint32_t portmask, uint8_t promisc_mode)
{
  int ret;
  uint8_t port_id, nb_ports;

  /* Get number of ports enabled via command line */
  nb_ports = rte_eth_dev_count();
  printf("the nb_ports is %d\n", nb_ports);

  /* Start all ports after all configuration has been done */
  for (port_id = 0; port_id < nb_ports; port_id++)
  {
    if ((portmask & (1 << port_id)) == 0)
    {
      continue;
    }
    //printf("1!\n");
    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
    {
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", ret,
               port_id);
    }
    if (promisc_mode == 1)
    {
      rte_eth_promiscuous_enable(port_id);
    }
    else
    {
      rte_eth_promiscuous_disable(port_id);
    }

    INIT_LOG("Successfully set up port %u\n", port_id);
  }
}

void init_app(struct app_global_config *app, struct app_lcore_params lcore[])
{
  // uint8_t nb_lcores = get_nb_lcores_available();

  // One core is reserved for control plane, two cores are reserved for SSD IO
  // operation nb_lcores -= 3;

  INIT_LOG("Initializing mbuf pools\n");
  init_mbuf_pools(app, lcore);

  /*d2worker worker2write write2worker worker2seaep write2seaep */
  INIT_LOG("Initializing ring queue and message pool \n");
  init_shm_rings(app, lcore);

  /*Only fwd core, excluding SSD IO core and control core, owns this data
   * structure */
  INIT_LOG("Initializing SEANET forwarding data structures (CS_TWO)\n");
  init_storage_data_structures(app, lcore);
  /*
  The nb_lcores will be used to configure the queue number of a port. Notice
  this value must set correct
  */
  INIT_LOG("Initializing ports\n");
  init_ports(app->portmask, 1, 2);

  /*Only fwd core, excluding SSD IO core and control core, will be binded with a
   * queue of a port */
  INIT_LOG("Initializing hardware queues\n");
  init_queues(app, lcore);

  INIT_LOG("Starting ports\n");
  start_ports(app->portmask, 1);

  INIT_LOG("Initialization complete\n");

  fflush(stdout);
}