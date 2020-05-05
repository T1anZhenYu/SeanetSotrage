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

//#define MULTICAST_QUERY_LOG(...) printf("[MULTICAST QUERY LOG]: " __VA_ARGS__)

int multicast_query_loop(__attribute__((unused)) void *arg) {
  struct app_lcore_params *conf;
  struct app_lcore_params *conf_mob;
  unsigned lcore_id;
  struct member_query_starter *mq_starter;

  lcore_id = rte_lcore_id();

  //struct rte_mbuf *mbuf = NULL;
  //struct local_resource_app_lcore_params *lr_conf = NULL;

  //lr_conf->lr = NULL;
  //lr_conf->conf = NULL;

  //MOBILE_LOG("[LCORE_%u] the muticast query core has Started\n", lcore_id);

  /* Get core configuration */
  conf = &lcore_conf[lcore_id];
  conf_mob = &lcore_conf[app_conf.lcore_configuration.mobile];
  //seaep_init(conf->send_ring, "2400:dd01:1037:101:192:168:101:16",
  //           "2400:dd01:1037:101:192:168:101:241", 1, 50);

  int ret = AE_OK;

  //lr_conf->lr = &lr;
  //lr_conf->conf = conf;
  while (1) {
    if (rte_ring_dequeue(conf->recv_ring, (void **)&mq_starter) == 0) {
		printf("member_query is starting~\n");
		/*uint8_t *sig = NULL, *mac = NULL, *ip = NULL, *eid = NULL;
		MAC_HEADER *mac_hdr = (MAC_HEADER *)lr.rev_buf;
		mac = mac_hdr->src_mac;
		IPV6_HEADER *ip_hdr = (IPV6_HEADER *)(lr.rev_buf + sizeof(MAC_HEADER));
		ip = ip_hdr->src_ip;
		sig = (uint8_t *)(lr.rev_buf + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER));
		uint16_t port_num = 0; 
		uint32_t pkt_len = 0, sig_len = 0;
		uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
		uint8_t *query_sig = NULL, *buf = NULL;
		printf("posts info is ready to be got~\n");
		eid = ((SIGNALLING *)sig)->eid;
		uint16_t *port_list = get_outports_from_forward_info_base(eid, &port_num);
		printf("query info is ready to build~\n");
		query_sig = query_info_constructor(eid, mac, ip, port_num, port_list, &sig_len);
		printf("query info is built~\n");
		if (query_sig == NULL)
			printf("oops!!\n");
		printf("sig_len = %d\n", sig_len);
		printf("member_query's sig_len = %d\n", sig_len);
		int i = 0;
		printf("%d\n",query_sig[0]);
		for (; i < sig_len; ++i)
		{
			//if (i % 12 == 0)
			//	printf("\n");
			printf("%d ", query_sig[i]);
		}
		printf("\n");
		buf = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, query_sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(buf, "Construct packet fail!");
		printf("Construct packet succeed\n");*/

		uint8_t* buf = calloc(1, BUFFLEN);
		uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0}, mtc_eid[20] = {0};

		UDP_HEADER* udp_hdr = calloc(1, sizeof(UDP_HEADER));
		MAC_HEADER* mac_hdr = calloc(1, sizeof(MAC_HEADER));
		IPV6_HEADER* ip_hdr = calloc(1, sizeof(IPV6_HEADER));
		SIGNALLING* sig_hdr = calloc(1, sizeof(SIGNALLING));

		mac_hdr = (MAC_HEADER *)buf;
		memcpy(mac_hdr->dst_mac, dst_mac, 6);
		memcpy(mac_hdr->src_mac, src_mac, 6);
		mac_hdr->type = htons(0x86dd);
		printf("Member query : Mac layer is done~\n");

		ip_hdr = (IPV6_HEADER *)(buf + sizeof(MAC_HEADER));
		ip_hdr->version_class_lable = htonl(0x60000000);
		ip_hdr->payload_len = htons(BUFFLEN - sizeof(MAC_HEADER) - sizeof(IPV6_HEADER));
		ip_hdr->next_header = 0x11;//udp
		ip_hdr->ttl = 10;
		memcpy(ip_hdr->src_ip, src_ip, 16);
		memcpy(ip_hdr->dst_ip, dst_ip, 16);
		printf("Member query : IPv6 layer is done~\n");

		udp_hdr = (UDP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER));
		udp_hdr->src_port = htons(SRC_PORT);
		udp_hdr->dst_port = htons(DST_PORT);
		udp_hdr->len = htons(126);
		udp_hdr->checksum = htons(check_sum((uint16_t *)udp_hdr, BUFFLEN - sizeof(EID_HEADER)));
		printf("Member query : UDP layer is done~\n");

		sig_hdr = (SIGNALLING *)(buf + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER));
		bzero(sig_hdr, sizeof(sig_hdr));
		sig_hdr->type_high = 0x4;
		sig_hdr->type_low = 0x1;
		sig_hdr->len = 0x14;
		memcpy(sig_hdr->eid, mtc_eid, 20);
		printf("Member query : Sig layer is done~\n");

		/*int i = 0;
		printf("member query:");
		for (; i < BUFFLEN; ++i)
		{
			if (i % 18 == 0)
				printf("\n");
			printf("%x ", buf[i]);
		}
		printf("\n");*/

	  	while (1)
		{
			int j = 0, k = 0;
			EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
			if (head == NULL)
			{
				printf("edge switch base is empty!\n");
				return AE_ERROR;
			}
			//printf("edge_switch_info_base.server_num = %d\n", edge_switch_info_base.server_num);
			//printf("the only port = %02X\n", edge_switch_info_base.edge_switch_info->ports[0].port);
			while (head != NULL)
			{
				for (; j < head->ports_num; ++j)
				{
					if (j >= head->ports_num)
						break;
					for (; k < head->ports[j].hosts_num; ++k)
					{
						if (k >= head->ports[j].hosts_num)
							break;
						if (head->ports[j].hosts[k].count >= 3)
						{
							//printf("k1 = %d\n", k);
							//ret = prune_sig_handler(head->multicast_service_eid, head->ports[j].port, &lr, conf);
							ret = quit_sig_query_handler(head->multicast_service_eid, head->ports[j].hosts[k].mac_addr, head->ports[j].hosts[k].host_ip, &lr, conf);
							//ret = quit_sig_handler(head->multicast_service_eid, head->ports[j].hosts[k].mac_addr, head->ports[j].hosts[k].host_ip, &lr, conf_mob);
							CHECK_INT_RETURN(ret, "member_query fail!");
							printf("Handle prune packet~\n");
  							printf("++++++++++++++++++++++++++++++++\n");
							//printf("head->ports[j].hosts_num = %d\n", head->ports[j].hosts_num);
							//printf("head->ports_num = %d\n", head->ports_num);
							//printf("edge_switch_info_base.server_num = %d\n", edge_switch_info_base.server_num);
							//printf("k2 = %d\n", k);
							return AE_OK;
							if (k >= head->ports[j].hosts_num)
								break;
							continue;
						}
						//int len = send_packet(buf, BUFFLEN, lr);
						//ret = sendtotxt_mc_query(buf, BUFFLEN, conf->send_ring);
						//printf("20191218 tag1\n");
						ret = rte_ring_enqueue(conf->send_ring, buf);
						CHECK_INT_RETURN(ret, "Send packet fail!");
						printf("Sent a member query pkt~\n");
						head->ports[j].hosts[k].count++;
					}
					k = 0;
					if (j >= head->ports_num)
						break;
				}
				j = 0;
				head = head->next;
			}
			mySleep(5);
		}
		//return AE_OK;
    }
    //seap_loop(NULL);
  }
}

int sendtotxt_mc_query(unsigned char *buffer, int bufferlen, struct rte_ring *r)
{
  printf("++++++++++++++++++++++++++++++++\n");

  //printfbuffer(buffer, bufferlen);
  //printf("sendtotxt_mc_query tag -1-\n");
  int sent = rte_ring_enqueue(r, buffer);
  //printf("sendtotxt_mc_query tag -2-\n");

  if (sent == 0)
  {
    printf("query send to txt succeed\n");
    return AE_OK;
  }
  else
  {
    printf("query send to txt failed\n");
    return AE_ERROR;
  }
  printf("++++++++++++++++++++++++++++++++\n");

}