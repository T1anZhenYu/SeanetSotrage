#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include "mobile_app.h"
#include "seaep_loop.h"

#include <rte_ring.h>
#include <sys/time.h>
#include "multicast_ae.h"

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

unsigned char src_portR[2] = {0x27, 0x10};  // 10000

unsigned char dst_port[2] = {0x27, 0x0f};   // 9999
unsigned char dst_port1[2] = {0x23, 0x28};  // 9000
unsigned char dst_portR[2] = {0x23, 0x29};  // 9001

unsigned int dstaddrv6[4] = {0, 0, 0, 1};
unsigned char SourceEid[20] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                               1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

unsigned char NEWNA[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 5};

typedef struct eth_header {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  unsigned char proto[2];
} eth_header;

typedef struct ipv6_header {
  unsigned char version_TypeofService_FlowTag[2];  // 16 bits
  unsigned char FlowTag[2];                        // 20bits
  unsigned char payloadLen[2];                     // 16bits,2B
  unsigned char nextHeader;                        // 8bits,1B
  unsigned char hopLimit;                          // 8bits,1B
  unsigned int srcipv6[4];                         // 128bits
  unsigned int dstipv6[4];                         // 128bits
} ipv6_header;

typedef struct udp_header {
  unsigned char srcPort[2];
  unsigned char dstPort[2];
  unsigned short len;
  unsigned short checksum;
} udp_header;

typedef struct eid_header {
  unsigned char proto;       // 1B
  unsigned char hdr_len;     // 1B
  unsigned short attr;       // 2B
  unsigned char srcEid[20];  // 20B
  unsigned char dstEid[20];  // 20B
} eid_header;

typedef struct mob_evt_info {
  struct rte_ring *r;
  unsigned char eth_ip_udp[62];   // ether,ip,udp
  char eid[EID_LEN];              // eid
  unsigned char orig_dst_NA[16];  //从移动事件消息中获取的移动前NA
  // unsigned char mob_mes[1500];//移动事件消息
  unsigned char srcna[1024];    // srcna
  int srcnanum;                 // srcna数量
  unsigned long int orig_time;  //起始时刻
  unsigned int delayParameter;  //最大允许超时，ms
  unsigned char status;         //表示是否已经得到满意的应答了
  unsigned char flag_already_timeout;  // 1表示已经超时，0表示未超时
  unsigned char flag_got_reply;  // 1表示已经得到应答，0表示未收到解析应答
} mob_evt_info;

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

typedef struct App_msg {
  unsigned char msg_type;       // 1B
  unsigned short msg_len;       // 2B
  unsigned char msg_txt[1500];  //最长为1500
} App_msg;

typedef struct MobApp_mobf_msg {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct eid_header eid_hdr;      // eid头部
  struct mobmess_hdr mobmesshdr;  //信令协议头部
} MobApp_mobf_msg;

//解析应答(成功)转发消息报文：
typedef struct resf_msg_s {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct eid_header eid_hdr;
  struct mobmess_hdr mobmesshdr;
  unsigned char newna[16];  //解析获得的新NA，16B
} resf_msg_s;

//解析应答(失败)转发消息报文：
typedef struct resf_msg_f {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct eid_header eid_hdr;
  struct mobmess_hdr mobmesshdr;
} resf_msg_f;

//解析应答(成功)通报消息报文：
typedef struct MobApp_res_msg_s {
  struct eth_header eth_hdr;  // mac头，拷贝移动事件消息mac头
  struct ipv6_header ipv6_hdr;  // IP头，基于移动事件消息ip头部修改字段
  struct udp_header udp_hdr;
  struct res_ack resack;    //
  unsigned char newna[16];  // 16B
} MobApp_res_msg_s;

//解析应答(失败)通报消息报文：
typedef struct MobApp_res_msg_f {
  struct eth_header eth_hdr;
  struct ipv6_hdr ipv6_hdr;
  struct udp_hdr udp_hdr;
  struct res_ack resack;
} MobApp_res_msg_f;

/*
unsigned long int current_time_ms(void) //time
{
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}
*/

////////////seaep
void print_eid(char eid[EID_LEN]) {
  char log_buffer[256];
  memset(log_buffer, 0, sizeof(log_buffer));
  strcat(log_buffer, "eid is: ");
  int i = 0;
  for (i = 0; i < EID_LEN; i++)
    sprintf(log_buffer + strlen(log_buffer), "%.2x ",
            ((unsigned char *)eid)[i]);
  strcat(log_buffer, " \n");
  printf(" eid is %s\n", log_buffer);
}

/*
int process_register_msg(void *context, Result_info *info)
{
    printf("register ok context %s\n",context);
    print_eid(info->eid);
    return 0;
}


int process_resolve_msg(void *context, Result_info *info)
{
    printf("resolve ok context %s\n",context);
    print_eid(info->eid);
    printf("seaep type = %d\n",info ->type);
    printf("seaep finished = %d\n",info ->finished);

   if(info->na_info){
   int i;
   for(i=0;i<info->na_info->na_num;i++)
       printf("nalist[%d] %s\n",i,info->na_info->na_list[i]);
   }


   return 0;
}
*/
//解析应答回调函数

void *process_resolve_msg(void *metadata, Result_info *info) {
  mob_evt_info *meta = (mob_evt_info *)metadata;
  printf("*********************\n");
  int i;
  unsigned int time;
  unsigned long int now_time = current_time_ms();
  printf("/////////////////now_time(us):%ld\n", now_time);  //毫秒
  time = now_time - meta->orig_time;
  printf("//////////////////time(us):%d\n", time);  //毫秒
  printf("seaep type = %d\n", info->type);
  printf("seaep finished = %d\n", info->finished);

  if (info->type == SEAEP_ACTION_RESPONSE_RESOLVE &&
      info->finished == SEAEP_RESULT_FAILED)  //????
  {
    printf("recv result %s\n", "failed");
    // printf("[[[[[[[[failed now_time(us):%ld\n",current_time_ms());  //毫秒
    mob_mes_constructionandsending(meta, NULL,
                                   3);  //构造并发送解析应答失败转发消息
    mob_resolveandsending(meta, NULL, 2);
    return NULL;
  }

  else if (info->type == SEAEP_ACTION_RESPONSE_RESOLVE &&
           info->finished == SEAEP_RESULT_SUCCESS) {
    printf("orig_time(us):%ld\n", meta->orig_time);           //毫秒
    printf("delayParameter(us):%d\n", meta->delayParameter);  //毫秒
    long now_time = current_time_ms();
    printf("now_time(us):%ld\n", now_time);  //毫秒

    time = now_time - meta->orig_time;
    printf("time(us):%d\n", time);  //毫秒

    if (time > meta->delayParameter)  //超时
    {
      printf("??????????????????time out+++++++++++++++++++++++\n");
      mob_mes_constructionandsending(meta, NULL,
                                     3);  //构造并发送解析应答失败转发消息
      mob_resolveandsending(meta, NULL, 2);
      return info;

    }

    else {
      unsigned char oldna[16];
      unsigned char newna[16];
      int j;
      int na_num;
      // unsigned char *na= (unsigned char *)malloc(16);

      memcpy(oldna, meta->orig_dst_NA, 16);
      printf("^^^^^^^^^^^^^^^^^^^^^old na=");
      for (i = 0; i < 16; i++) printf("%d ", oldna[i]);
      printf("\n");

      na_num = info->na_info->na_num;  //去na_num
      printf("^^^^^^nanum=%d\n", na_num);
      int c;

      for (i = 0; i < na_num; i++) {
        inet_pton(AF_INET6, (char *)info->na_info->na_list[i], newna);
        // memcpy(newna, info ->na_info ->na_list[i], 16);//将新na拷入newna
        printf("^^^^^^^^^^^^^^^^^^^^^new na=");
        for (c = 0; c < 16; c++) printf("%d ", newna[c]);
        printf("\n");
        // flag=0;
        for (j = 0; j < 16; j++) {
          if (oldna[j] != newna[j]) {
            meta->status = 1;
            break;
          }
        }
        if (meta->status != 0) break;
      }

      if (meta->status == 1) {
        // unsigned char newna[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        mob_mes_constructionandsending(meta, newna,
                                       2);  //构造并发送解析应答转发消息
        mob_resolveandsending(meta, newna, 1);
        return info;

      } else {
        printf("++++++\n");
        //再次解析查询
        seaep_start_resolve(meta->eid, meta, 200, process_resolve_msg);
        return info;
      }
    }
  } else {
    printf("++++++\n");

    return info;
  }
}

/*
int process_unregister_msg(void *context, Result_info *info)
{
    printf("unregister ok context %s\n",context);
    print_eid(info->eid);

    return 0;
}
*/

int mobile_process_loop(__attribute__((unused)) void *arg) {
  struct app_lcore_params *conf;
  struct app_lcore_params *conf_mc_query;
  unsigned lcore_id;
  struct ether_hdr *eth_hdr;
  struct ipv6_hdr *ipv6_hdr;
  struct udp_hdr *udp_hdr;
  uint16_t src_port, dst_port;

  unsigned char packet[1500] = {0};
  char eid[20] = {0};
  int n;
  // int i;
  int srcnalen;

  lcore_id = rte_lcore_id();

  struct rte_mbuf *mbuf = NULL;
  mc_query_info* mcquery = NULL;
  char* buf_query = calloc(10, BUFFLEN);

  MOBILE_LOG("[LCORE_%u] the moblie app core has Started\n", lcore_id);

  /* Get core configuration */
  conf = &lcore_conf[lcore_id];
  conf_mc_query = &lcore_conf[app_conf.lcore_configuration.multicast];
  seaep_init(conf->send_ring, "2400:dd01:1037:101:192:168:101:16",
             "2400:dd01:1037:101:192:168:101:241", 1, 50);

  int ret = AE_OK;
  //struct local_resource lr;
  //struct local_resource_app_lcore_params lr_conf;

  /*ret = multicast_ae_init(&lr);
  CHECK_INT_RETURN(ret, "multicast init failed!\n");*/
  // Check whether the eid is root id. If not, QUIT.
  ret = check_root();
  CHECK_INT_RETURN(ret, "Not an root user!");

  ret = info_base_init();
  CHECK_INT_RETURN(ret, "Init info base fail!");

  // Initialize the local resource.
  ret = local_resource_init(&lr);
  CHECK_INT_RETURN(ret, "Init local resource fail!");

  //lr_conf.conf = conf;
  //lr_conf.lr = &lr;

  // Delay for finishing the initlization started above.
  sleep(1);
  printf("multicast init is finished~\n");

  while (1) {
    if (rte_ring_dequeue(conf->recv_ring, (void **)&mbuf) == 0) {
      if (mbuf->ol_flags == MOBILE_TYPE) {
        printf("+++++++++++++++++++++++++++++++\n");
        printf("I have received a mb event msg!\n");
        eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        ipv6_hdr =
            (struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
        udp_hdr =
            (struct udp_hdr *)RTE_PTR_ADD(ipv6_hdr, sizeof(struct ipv6_hdr));

        src_port = ntohs(udp_hdr->src_port);
        dst_port = ntohs(udp_hdr->dst_port);

        printf("the mb event msg src port is %d\n", src_port);
        printf("the mb event msg dst port is %d\n", dst_port);

        // char *metadata=(char *)"hello world";

        memcpy(packet, rte_pktmbuf_mtod(mbuf, void *), mbuf->data_len);
        // printf("packet len is %d\n",mbuf->data_len);
        srcnalen = mbuf->data_len - 102;
        n = srcnalen / 16;

        printf("srcnanum =%d\n", n);

        rte_pktmbuf_free(mbuf);  //释放mbuf

        memcpy(eid, packet + 82, 20);  // eid获取

        // seaep_start_register(eid,metadata,500, 7, 1,process_register_msg);
        // seaep_start_resolve(eid,metadata,20,process_resolve_msg);
        // seaep_start_unregister(eid,metadata,process_unregister_msg);

        /*
        printf("eid=");
        for(i=0;i<20;i++)
        {
        printf("%d ",eid[i]);
         }
        printf("\n");
        */

        ////////
        mob_evt_info *metadata = (mob_evt_info *)malloc(sizeof(mob_evt_info));  //分配一块动态连续内存
        metadata->r = conf->send_ring;
        memcpy(metadata->eth_ip_udp, packet, 62);        // ether,io,udp
        memcpy(metadata->eid, eid, 20);                  // eid获取
        memcpy(metadata->orig_dst_NA, packet + 66, 16);  // oldna
        // unsigned char oldna[16]={36,0,221,1,16,55,1,1,1,146,1,104,1,1,0,9};
        // memcpy(metadata ->orig_dst_NA, oldna, 16);//oldna
        // memcpy(metadata ->mob_mes, packet, mbuf->data_len);//mob_message
        memcpy(metadata->srcna, packet + 102, srcnalen);  // srcna
        metadata->srcnanum = n;
        // printf("^^^^^^^^^metadata srcnanum=%d\n",metadata ->srcnanum);
        metadata->orig_time = current_time_ms();
        metadata->delayParameter = DELAYTIME;
        // printf("^^^^^^^^^^^orig_time(us):%ld\n",metadata->orig_time);  //毫秒
        metadata->status = 0;  //满意标志
        metadata->flag_already_timeout = 0;
        metadata->flag_got_reply = 0;

        //构造并发送移动事件转发消息
        // printf("*********************************\n");
        mob_mes_constructionandsending(metadata, NULL, 1);
        // printf("*********************************\n");

        seaep_start_resolve(eid, metadata, 200, process_resolve_msg);
        /*
        mob_mes_constructionandsending(metadata, NEWNA, 2);
        printf("*********************************\n");

        mob_mes_constructionandsending(metadata, NULL, 3);
        printf("*********************************\n");

        mob_resolveandsending(metadata, NEWNA, 1);
        printf("*********************************\n");
        mob_resolveandsending(metadata, NULL, 2);
        printf("*********************************\n");
        */
        //注册
        // seaep_register(eid, 500, 5, 1);//注册eid

        // char out_data[1024];

        //解析查询
        // int ret = seaep_resolve_outdata_async(eid, metadata,10,
        // process_resolve_msg_outdata); printf("ret is %d\n",ret);
        // printf("^^^^^^^^^metadata status=%d\n",metadata ->status");//

        // seaep_unregister(eid);//注销

        // TODO : (zeng): free?
        /////
      } 
      else if (mbuf->ol_flags == MULTICAST_TYPE) {
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        printf("I have received a multicast event msg!\n");

        //memcpy(lr->rev_buf, rte_pktmbuf_mtod(mbuf, void *), mbuf->pkt_len);
        //memset(lr->rev_buf, 0, BUFFER_SIZE);
        memcpy(lr.rev_buf, rte_pktmbuf_mtod(mbuf, void *), mbuf->data_len);

        if(mbuf->data_len <=0){
            continue;
        }

        /* Check the packet length. */
        if(mbuf->data_len > MTC_SIG_MTU_LENGTH){
            printf("ERROR: The packet received is longer than MTU.\n");
            continue;
        }

        /* Parse the received packet. */
        ret = packet_parser(lr.rev_buf, mbuf->data_len, &lr, conf);
        printf("Parse packet succeed! ret = %d\n", ret);
        CHECK_INT_RETURN(ret, "Parse packet fail!");

        /* Start cli module. */
        ret = cli_init();
        CHECK_INT_RETURN(ret, "Init cli fail!");
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
      }
      else if (mbuf->ol_flags == SEAEP_TYPE) {
        printf("I have received a seaep event msg!\n");
        seap_loop(mbuf);
      }
    }
    //else if(rte_ring_dequeue(conf_mc_query->send_ring, (void **)&mcquery) == 0)
    else if(rte_ring_dequeue(conf_mc_query->send_ring, (void **)&buf_query) == 0)
    {
      printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nHere comes the query info~\n");
      /*int tmp = 0;
      printf("mcquery : \n");
      for (; tmp < BUFFLEN; tmp++)
      {
        if (tmp % 18 == 0)
          printf("\n");
        printf("%x\n", mcquery[tmp]);
      }
      printf("\n");*/
      sendtotxt_multicast(buf_query, BUFFLEN, conf->send_ring);
      //rte_ring_enqueue(conf->send_ring, mcquery);
      //rte_ring_enqueue(conf->send_ring, buf_query);
      printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    }
    seap_loop(NULL);
  }
}

//发包函数
void sendtotxt(unsigned char *buffer, int bufferlen, struct rte_ring *r) {
  // printf("++++++++++++++++++++++++++++++++\n");
  sendpacket *send_data = (sendpacket *)malloc(sizeof(sendpacket));  //???
  send_data->packet = (unsigned char *)malloc(256);
  send_data->type = MOBILE_TYPE;
  send_data->len = bufferlen;
  memcpy(send_data->packet, buffer, bufferlen);

  printfbuffer(buffer, bufferlen);

  if (rte_ring_enqueue(r, send_data) == 0)
    printf("send to txt succeed\n");
  else
    printf("send to txt failed\n");
  printf("++++++++++++++++++++++++++++++++\n");
}

//core dump


int sendtotxt_multicast(unsigned char *buffer, int bufferlen, struct rte_ring *r) {
  // printf("++++++++++++++++++++++++++++++++\n");
  sendpacket *send_data = (sendpacket *)calloc(1, sizeof(sendpacket));
  send_data->packet = (unsigned char *)calloc(1, 256);
  send_data->type = MULTICAST_TYPE;
  send_data->len = bufferlen;
  memcpy(send_data->packet, buffer, bufferlen);

  // printf("sendtotxt_multicast tag1\n");
  // printf("bufferlen = %d\n", bufferlen);
  // printf("is buffer == NULL : %d\n", buffer == NULL);

  printfbuffer(buffer, bufferlen);

  //printf("");

  int sent = rte_ring_enqueue(r, send_data);

  if (sent == 0)
  {
    printf("send to txt succeed\n");
    return AE_OK;
  }
  else
  {
    printf("send to txt failed\n");
    return AE_ERROR;
  }
  printf("++++++++++++++++++++++++++++++++\n");
}

//移动事件转发消息、解析应答转发消息
void mob_mes_constructionandsending(void *message, unsigned char *newna,
                                    int fun_c) {
  int buffer_len;
  // int i;
  int j;
  int src_len;

  unsigned char mob_buffer[BUFFSIZEMOBFR] = {0};

  if (newna == NULL)  //
  {
    buffer_len = BUFFSIZEMOBF;  //移动时间转发消息,解析失败
  } else {
    buffer_len = BUFFSIZEMOBFR;  //解析成功
  }

  mob_evt_info *mob_meta = (mob_evt_info *)message;
  memcpy(mob_buffer, mob_meta->eth_ip_udp, 54);  // mac+ip头
  ipv6_header *iphdr =
      (struct ipv6_header *)(mob_buffer + sizeof(struct eth_header));
  iphdr->payloadLen[1] = 0x32;
  iphdr->nextHeader = 0x99;
  memcpy(iphdr->dstipv6, dstaddrv6, 16);  // dstip固定值
  eid_header *eidhdr =
      (struct eid_header *)(mob_buffer + sizeof(struct eth_header) +
                            sizeof(struct ipv6_header));
  eidhdr->proto = 2;             // 0x02
  eidhdr->hdr_len = 0x2c;        // 44Byte
  eidhdr->attr = htons(0x0002);  // mobility
  memcpy(eidhdr->srcEid, SourceEid, 20);
  memcpy(eidhdr->dstEid, mob_meta->eid, 20);
  mobmess_hdr *messhdr =
      (mobmess_hdr *)(mob_buffer + sizeof(struct eth_header) +
                      sizeof(struct ipv6_header) + sizeof(struct eid_header));
  messhdr->mes_type = 0x10;

  switch (fun_c) {
    case 1:  //移动事件转发消息
    {
      // printf("++++++++++++mob f+++++++++++++++\n");
      break;
    }
    case 2:  //解析应答成功转发消息
    {
      iphdr->payloadLen[1] = 0x42;
      messhdr->mes_type = 0x11;
      messhdr->payload_len[0] = 0;
      messhdr->payload_len[1] = 16;
      memcpy(mob_buffer + 104, newna, 16);
      // printf("++++++++++++resolve SUCCEED+++++++++++++++\n");
      break;
    }
    case 3:  //解析应答失败转发消息
    {
      // printf("++++++++++++resolve FAILED+++++++++++++++\n");
      messhdr->mes_type = 0x11;
      break;
    }
    default:
      return;
  }

  for (j = 0; j < mob_meta->srcnanum; j++) {
    src_len = 16 * j;
    // printf("send %d buffer\n",j+1);
    memcpy(iphdr->srcipv6, mob_meta->srcna + src_len, 16);  // srcna获取
    // printf("len =%d\n",buffer_len);
    // eid
    /*
    printf("eid=");
    for(i=0;i<20;i++)
    {
        printf("%d ",mob_buffer[i+78]);
    }
    printf("\n");
    //srcna
    printf("srcna=");
    for(i=0;i<16;i++)
    {
        printf("%d ",mob_buffer[i+22]);
    }
    printf("\n");
    */
    // printf("++++++++++++++\n");
    // printfbuffer(mob_buffer,buffer_len);
    sendtotxt(mob_buffer, buffer_len, mob_meta->r);
    // printf("---------------\n");
  }
}

//解析应答通告消息
void mob_resolveandsending(void *message, unsigned char *newna, int fun_c) {
  int reslen;
  // int i;

  if (newna == NULL)  //
  {
    reslen = BUFFSIZERESOLVEF;  //
  } else {
    reslen = BUFFSIZERESOLVES;  //
  }
  // printf("===========reslen=%d\n",reslen);
  mob_evt_info *mob_meta = (mob_evt_info *)message;
  unsigned char res_buffer[BUFFSIZERESOLVES] = {0};
  memcpy(res_buffer, mob_meta->eth_ip_udp, 54);  // mac+ip头
  ipv6_header *iphdr = (struct ipv6_header *)(res_buffer + sizeof(eth_header));
  iphdr->payloadLen[1] = reslen - sizeof(eth_header) - sizeof(ipv6_header);
  udp_header *udphdr =
      (udp_header *)(res_buffer + sizeof(eth_header) + sizeof(ipv6_header));
  memcpy(udphdr->srcPort, src_portR, 2);
  memcpy(udphdr->dstPort, dst_portR, 2);

  udphdr->len = htons(reslen - sizeof(eth_header) - sizeof(ipv6_header));
  // udphdr->checksum = htons(check_sum((unsigned short *)udphdr, reslen ));

  res_ack *resolve = (res_ack *)(res_buffer + sizeof(eth_header) +
                                 sizeof(ipv6_header) + sizeof(udp_header));
  resolve->type = 12;
  resolve->status = 1;
  memcpy(resolve->eid, mob_meta->eid, 20);
  resolve->num = 1;

  switch (fun_c) {
    case 1:  //成功
    {
      // printf("++++++++++++res s+++++++++++++++\n");
      memcpy(res_buffer + 85, newna, 16);

      // memcpy(na,resolve ->new_ip,16);
      /*
          printf("new na=");
          for(i=0;i<16;i++)
              printf("%d ", res_buffer[i+85]);
          printf("\n");
          */

      break;
    }
    case 2:  //失败
    {
      resolve->status = 0;
      // printf("++++++++++++res f+++++++++++++++\n");
      break;
    }

    default:
      return;
  }

  //发送
  // printfbuffer(res_buffer,reslen);
  sendtotxt(res_buffer, reslen, mob_meta->r);
}

//十六进制打印包
void printfbuffer(unsigned char *buffer, int buffer_len) {
  int i = 0;
  // printf("buffer:");
  // printf("printfbuffer tag1\n");
  // printf("buffer_len = %d\n", buffer_len);
  // printf("if buffer == NULL : %d\n", buffer == NULL);
  for (i = 0; i < buffer_len; i++) 
  {
    //if (i % 18 == 0)
    //  printf("\n");
    printf("%x ", buffer[i]);
  }
  printf("\n");
  // printf("printfbuffer tag2\n");
}

//将IP地址转换为字符串输出
int addr_is_ipv4(char ip_addr[16]) {
  int value = 0, i;
  for (i = 0; i < 12; i++) {
    value |= ip_addr[i /*+4*/];
  }
  if (!value) {
    return 1;
  }
  return 0;
}

char *netbytes2ip(char *ip) {
  static char buf[128];

  if (addr_is_ipv4((char *)ip)) {
    in_addr_t addr;
    int j;
    char *addr_data = (char *)ip;
    char *y = (char *)&addr;
    for (j = 0; j < 4; j++) {
      y[j] = addr_data[j + 12];
    }
    if (inet_ntoa(*(struct in_addr *)&addr))
      return inet_ntoa(*(struct in_addr *)&addr);
  } else {
    struct sockaddr_in6 dst;
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_flowinfo = 0;
    dst.sin6_scope_id = 0;
    memcpy(&dst.sin6_addr, ip, 16);

    memset(buf, 0, 128);
    inet_ntop(AF_INET6, &dst.sin6_addr, buf, sizeof(buf));
    return buf;
  }
  return NULL;
}

void ByteToHexStr(const unsigned char *source, unsigned char *dest,
                  int sourceLen) {
  short i;
  unsigned char highByte, lowByte;

  for (i = 0; i < sourceLen; i++) {
    highByte = source[i] >> 4;
    lowByte = source[i] & 0x0f;
    highByte += 0x30;

    if (highByte > 0x39)
      dest[i * 2] = highByte + 0x07;
    else
      dest[i * 2] = highByte;

    lowByte += 0x30;
    if (lowByte > 0x39)
      dest[i * 2 + 1] = lowByte + 0x07;
    else
      dest[i * 2 + 1] = lowByte;
  }
}

/*int multicast_ae_init(struct local_resource *lr)
{
    int ret = AE_OK;
    // Check whether the euid is root id. If not, QUIT.
    ret = check_root();
    CHECK_INT_RETURN(ret, "Not an root user!");

    ret = info_base_init();
    CHECK_INT_RETURN(ret, "Init info base fail!");

    // Initialize the local resource.
    ret = local_resource_init(&lr);
    CHECK_INT_RETURN(ret, "Init local resource fail!");

    // Delay for finishing the initlization started above.
    //sleep(1);
    printf("hello there~tag 1\n");
    return ret;
}*/

int local_resource_init(struct local_resource *lr) {
    lr->dev_name = "lo";
    lr->dev_ip = "::1/128";
    //lr->switch_ip = ;
    lr->mtc_sev_num = MAX_MULTICAST_NUM;
    lr->host_num = MAX_HOST_NUM_PER_MULTICAST;
    lr->edge_flag = FALSE;
    //lr->member_query_thread = NULL;
    //lr->rev_buf[BUFFER_SIZE] = {0};
    //lr->send_buf[BUFFER_SIZE] = {0};

    return AE_OK;
}

int cli_init() {

    return AE_OK;
}



