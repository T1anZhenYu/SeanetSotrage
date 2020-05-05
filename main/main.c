/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <rte_log.h>

//#include "/home/dsp/dpdk-2.0.0/lib/librte_eal/common/eal_internal_cfg.h"

//#include "seanet_packet_prase.h"
#include "init.h"
#include "Defaults.h"
#include "Data_plane.h"
#include "dispatch_core.h"
#include "mobile_app.h"
#include "tx_action.h"
#include "util.h"
#include "writer_core.h"
#include "multicast_ae.h"

#define MAIN_LOG(...) RTE_LOG(DEBUG, USER1, "[MAIN]: " __VA_ARGS__)

#define DEBUG

/* uncommnet below line to enable debug logs */
/* #define DEBUG */

#ifdef DEBUG
#define LOG_LEVEL RTE_LOG_DEBUG
#define LOG_DEBUG(log_type, fmt, args...)  \
  do                                       \
  {                                        \
    RTE_LOG(DEBUG, log_type, fmt, ##args); \
  } while (0)
#else
#define LOG_LEVEL RTE_LOG_INFO
#define LOG_DEBUG(log_type, fmt, args...) \
  do                                      \
  {                                       \
  } while (0)
#endif

#define RTE_LOGTYPE_DISTRAPP RTE_LOGTYPE_USER1

/* mask of enabled ports */
static uint32_t enabled_port_mask;
volatile uint8_t quit_signal;
volatile uint8_t quit_signal_rx;

static volatile struct app_stats
{
  struct
  {
    uint64_t rx_pkts;
    uint64_t returned_pkts;
    uint64_t enqueued_pkts;
  } rx __rte_cache_aligned;

  struct
  {
    uint64_t dequeue_pkts;
    uint64_t tx_pkts;
  } tx __rte_cache_aligned;
} app_stats;

struct app_global_config app_conf;
struct app_lcore_params lcore_conf[APP_MAX_LCORES];

static void signal_handler(int sig_num)
{
  printf("Exiting on signal %d\n", sig_num);
  /* set quit flag for rx thread to exit */
  print_stats();
  exit(0);
}

static void print_usage(const char *prgname)
{
  printf(
      "\n %s [EAL options] -- -p PORTMASK -k PAIRS NUMBER\n"
      "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
      "  -k PAIRS NUMBER: the pairs number of assemble core and storage core to configure\n",
      prgname);
}

static int parse_portmask(const char *portmask)
{
  char *end = NULL;
  unsigned long pm;

  /* parse hexadecimal string */
  pm = strtoul(portmask, &end, 16);
  if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
    return -1;

  if (pm == 0)
    return -1;

  return pm;
}

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
  int opt;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {{NULL, 0, 0, 0}};

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "p:k:", lgopts, &option_index)) !=
         EOF)
  {
    switch (opt)
    {
    /* portmask */
    case 'p':
      enabled_port_mask = parse_portmask(optarg);
      if (enabled_port_mask == 0)
      {
        printf("invalid portmask\n");
        print_usage(prgname);
        return -1;
      }
      break;

    default:
      print_usage(prgname);
      return -1;
    }
  }

  if (optind <= 2)
  {
    print_usage(prgname);
    return -1;
  }

  argv[optind - 1] = prgname;

  optind = 0; /* reset getopt lib */
  return 0;
}

/* Main function, does initialization and calls the per-lcore functions */
int main(int argc, char *argv[])
{
  printf("Compiled on %s %s\n", __DATE__, __TIMESTAMP__);
  int ret;

  unsigned lcore_id;
  uint8_t nb_ports;

  time_t eal_init_begin_time, eal_init_end_time;
  time_t init_app_begin_time, init_app_end_time;

  /* catch ctrl-c so we can print on exit */
  signal(SIGINT, signal_handler);

  time(&eal_init_begin_time);

  /* set log */
  //FILE *fp_log;
  //if ((fp_log = fopen("log.txt", "w")) == NULL) {
  //  rte_exit(EXIT_FAILURE, " ERR open log");
  //}
  //if (rte_openlog_stream(fp_log) < 0) {
  //  rte_exit(EXIT_FAILURE, " ERR log");
  //}

  //MAIN_LOG("eal init begin time: %s", ctime(&eal_init_begin_time));
  /* init EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  argc -= ret;
  argv += ret;
  rte_log_set_global_level(RTE_LOG_DEBUG);
  // rte_set_log_level(RTE_LOG_DEBUG);
  // rte_set_log_level(RTE_LOG_ERR);

  time(&eal_init_end_time);
  MAIN_LOG("eal init end time: %s \n", ctime(&eal_init_end_time));

  fflush(stdout);

  if (rte_lcore_count() < 3)
    rte_exit(EXIT_FAILURE,
             "Error, This application needs at "
             "least 3 logical cores to run:\n"
             "1 lcore for packet RX and distribution\n"
             "1 lcore for packet TX\n"
             "and at least 1 lcore for worker threads\n");

  /* parse application arguments (after the EAL ones) */
  ret = parse_args(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid storage end parameters\n");

  // Configure the app config object

  /* Packet burst settings */
  app_conf.tx_burst_size = MAX_PKT_BURST; // 32
  app_conf.rx_burst_size = MAX_PKT_BURST; // 32
  /* Packet pool settings */
  app_conf.nb_mbuf = NB_MBUF;                       // 32765
  app_conf.mbuf_size = MBUF_SIZE;                   //(4096 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
  app_conf.mempool_cache_size = MEMPOOL_CACHE_SIZE; // 256
  
  /*lcore setting*/
  app_conf.lcore_configuration.master = 0;
  app_conf.lcore_configuration.dispatch = 1;
  app_conf.lcore_configuration.mobile = 2;
  app_conf.lcore_configuration.multicast = 3;
  app_conf.lcore_configuration.tx_1 = 4;
  app_conf.lcore_configuration.tx_2 = 5;

  app_conf.lcore_configuration.core_pairs = 3;
  int count = 0;
  for (count = 0; count < app_conf.lcore_configuration.core_pairs; count++)
  {
    app_conf.lcore_configuration.worker[count] = count + 6;
    app_conf.lcore_configuration.writer[count] = count + 6 + WORKER_WRITER_ID_DIFFER_NUM;
  }

  /*get fs space*/
  app_conf.fs_space = 2.7 * 1024 * 1024 * 1024 * 1024;//2.7T
  app_conf.bucket_num_for_cs_two = app_conf.fs_space 
          / SIZE_OF_ONE_CHUNK 
          / app_conf.lcore_configuration.core_pairs
          * EXTEND_FACTOR_OF_HASH_TABLE;

  /* Other config */
  app_conf.portmask = enabled_port_mask;

  nb_ports = rte_eth_dev_count();
  if (nb_ports == 0)
    rte_exit(EXIT_FAILURE, "Error: no ethernet ports detected\n");
  if (nb_ports != 1 && (nb_ports & 1))
    rte_exit(EXIT_FAILURE,
             "Error: number of ports must be even, excquit_signal_rxt "
             "when using a single port\n");

  time(&init_app_begin_time);
  MAIN_LOG("init app begin time: %s", ctime(&init_app_begin_time));
  fflush(stdout);

  init_app(&app_conf, lcore_conf);

  time(&init_app_end_time);
  MAIN_LOG("init app end time: %s \n", ctime(&init_app_end_time));

  reset_stats();

  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1, "\n");
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
          "--------------------------------------------------\n");
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
          "-----------------  begin ----------------\n");

  // printf("the macro is %d\n",MAX_HUGEPAGE_SIZES);

  fflush(stdout);

  for (lcore_id = 0; lcore_id < APP_MAX_LCORES; lcore_id++)
  {
    // if (worker_id == rte_lcore_count() - 2)
    //	rte_eal_remote_launch((lcore_function_t *)lcore_tx,
    //			output_ring, lcore_id);
    if (!rte_lcore_is_enabled(lcore_id))
    {
      continue;
    }

    // Skip master core
    if (lcore_id == app_conf.lcore_configuration.master)
    {
      continue;
    } // 0

    if (lcore_id == app_conf.lcore_configuration.dispatch)
    {
      RTE_LOG(DEBUG, EAL, "[LCORE_%u] dispatch core Started\n", lcore_id);
      ret = rte_eal_remote_launch(dispatch_loop, NULL, lcore_id);
      if (ret < 0)
      {
        rte_exit(EXIT_FAILURE, "Pkt dispatch lcore %u busy \n", lcore_id);
      }
    }

    int iter = 0;
    for(iter = 0; iter < app_conf.lcore_configuration.core_pairs; iter++)
    {
      if (lcore_id == app_conf.lcore_configuration.writer[iter])
      {

        printf("[LCORE_%u] writer core Started\n", lcore_id);
        RTE_LOG(DEBUG, EAL, "[LCORE_%u] writer core Started\n", lcore_id);
        ret = rte_eal_remote_launch(fs_io_loop, NULL, lcore_id);
        if (ret < 0)
        {
          rte_exit(EXIT_FAILURE, "write lcore %u busy \n", lcore_id);
        }
        break;
      }

      if (lcore_id == app_conf.lcore_configuration.worker[iter])
      {
        RTE_LOG(DEBUG, EAL, "[LCORE_%u] worker core Started\n", lcore_id);
        ret = rte_eal_remote_launch(seanet_packet_process_loop, NULL, lcore_id);
        if (ret < 0)
        {
          rte_exit(EXIT_FAILURE, "worker lcore %u busy \n", lcore_id);
        }
        break;
      }
    }

    if (lcore_id == app_conf.lcore_configuration.mobile)
    {
      RTE_LOG(DEBUG, EAL, "[LCORE_%u] mobile core Started\n", lcore_id);
      ret = rte_eal_remote_launch(mobile_process_loop, NULL, lcore_id);
      if (ret < 0)
      {
        rte_exit(EXIT_FAILURE, "mobile lcore %u busy \n", lcore_id);
      }
    }

    if (lcore_id == app_conf.lcore_configuration.tx_1 || lcore_id == app_conf.lcore_configuration.tx_2)
    {
      RTE_LOG(DEBUG, EAL, "[LCORE_%u] tx core Started\n", lcore_id);
      ret = rte_eal_remote_launch(tx_process_loop, NULL, lcore_id);
      if (ret < 0)
      {
        rte_exit(EXIT_FAILURE, "TX lcore %u busy \n", lcore_id);
      }
      continue;
    }
    if (lcore_id == app_conf.lcore_configuration.multicast)
    {
      RTE_LOG(DEBUG, EAL, "[LCORE_%u] multicast lookup core Started\n", lcore_id);
      ret = rte_eal_remote_launch(multicast_query_loop, NULL, lcore_id);
      if (ret < 0)
      {
        rte_exit(EXIT_FAILURE, "MULTICAST LOOKUP lcore %u busy \n", lcore_id);
      }
      continue;
    }

    continue;
  }

  fflush(stdout);

  // wait for each lcore to finish its task
  RTE_LCORE_FOREACH_SLAVE(lcore_id)
  {
    if (rte_eal_wait_lcore(lcore_id) < 0)
    {
      return -1;
    }
  }

  print_stats();
  return 0;
}
