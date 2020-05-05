#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>  
#include "multicast_ae.h"


unsigned short check_sum(unsigned short *addr,int len)
{
        register int nleft=len;
        register int sum=0;
        register short *w=addr;
        short answer=0;

        while(nleft>1)
        {
                sum+=*w++;
                nleft-=2;
        }
        if(nleft==1)
        {
                *(unsigned char *)(&answer)=*(unsigned char *)w;
                sum+=answer;
        }

        sum=(sum>>16)+(sum&0xffff);
        sum+=(sum>>16);
        answer=~sum;
        return(answer);
}

/*int send_packet(uint8_t *buf, uint32_t buf_len, struct local_resource *lr) {
    struct   sockaddr_ll sockadr;
    struct   ifreq ethreq;
    int      sock, len = 0, ret = AE_OK;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	CHECK_INT_RETURN(sock, "Creat socket fail!---tag5");

	//Get network interface.
	//strncpy(ethreq.ifr_name, lr->dev_name, IFNAMSIZ);
	strncpy(ethreq.ifr_name, "ens33", IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFINDEX, &ethreq);// get network interface
    CHECK_INT_RETURN(ret, "Ioctl fail!");

	bzero(&sockadr, sizeof(struct  sockaddr_ll));
	sockadr.sll_ifindex = ethreq.ifr_ifindex;

	len = sendto(sock, buf, buf_len, 0, (struct sockaddr *)&sockadr, sizeof (sockadr));
	CHECK_INT_RETURN(len, "Send packet fail! - 1 -");

	return AE_OK;
}*/

uint8_t * udp_packet_constructor(uint8_t *src_mac, uint8_t *dst_mac, uint8_t *src_ip, uint8_t *dst_ip, uint8_t *sig, uint32_t sig_len, uint32_t *buf_len) {
	uint8_t *buf = NULL;
	*buf_len = 62 + sig_len;

	buf = calloc(1, *buf_len);
	if (NULL == buf) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	MAC_HEADER *mac_hdr;
	IPV6_HEADER *ip_hdr;
	UDP_HEADER *udp_hdr;

	mac_hdr = (MAC_HEADER *)buf;
	memcpy(mac_hdr->dst_mac, dst_mac, 6);
	memcpy(mac_hdr->src_mac, src_mac, 6);
	mac_hdr->type = htons((short)0x86DD);

	ip_hdr = (IPV6_HEADER *)(buf + sizeof(MAC_HEADER));
	ip_hdr->version_class_lable = htonl((int)1073741824);
	ip_hdr->payload_len = htons((short)(8 + sig_len));
	ip_hdr->next_header = 17;
	ip_hdr->ttl = 10;
	memcpy(ip_hdr->src_ip, src_ip, 16);
	memcpy(ip_hdr->dst_ip, dst_ip, 16);

	udp_hdr = (UDP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER));
	udp_hdr->src_port = htons((short)SRC_PORT);
	udp_hdr->dst_port = htons((short)DST_PORT);
	udp_hdr->len = htons((short)sig_len);
	udp_hdr->checksum = htons(check_sum((uint16_t *)udp_hdr, *buf_len));

	//printf("udp - 1 -\n");
	/*printf("udp constructor's sig_len = %d\n", sig_len);
	int i = 0;
	for (; i < sig_len; ++i)
		printf("%d ", sig[i]);
	printf("\n");*/
	memcpy(buf + 62 , sig, sig_len);
	//printf("udp - 2 -\n");
	free(sig);
	//sig = NULL;

	//printf("udp - 3 -\n");
	return buf;
}

uint8_t * join_info_constructor(uint8_t *eid, uint8_t *mac, uint8_t *ip, uint16_t port_num, uint16_t *port_list, uint32_t *buf_len) {
	uint8_t *buf = NULL;
	int32_t i;
	JOIN_INFO_SIG *join_info = NULL;

	if (port_num % 2 == 0) {
		*buf_len = 4 + 20 + 16 + 6 + 2 + port_num * 2;
	} else {
		*buf_len = 4 + 20 + 16 + 6 + 2 + port_num * 2 + 1;
	}
	
	buf = calloc(1, *buf_len);
	if (NULL == buf) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	join_info = (JOIN_INFO_SIG *)buf;
	join_info->type_low = 1;
	join_info->type_high = 3;
	join_info->len = htons((short)(*buf_len - 4));
	memcpy(join_info->eid, eid, 20);
	memcpy(join_info->ip, ip, 16);
	memcpy(join_info->mac, mac, 6);
	join_info->port_num = htons((short)port_num);

	for (i = 0; i < port_num; ++i)
	{
		*(buf + sizeof(JOIN_INFO_SIG) + i) = htons((short)(*(port_list + i)));
	}

	if (port_num % 2 != 0) {
		*(buf + *buf_len - 1) = 0;
	} 

	return buf;
}


uint8_t * query_info_constructor(uint8_t *eid, uint8_t *mac, uint8_t *ip, uint16_t port_num, uint16_t *port_list, uint32_t *buf_len) {
	uint8_t *buf = NULL;
	int32_t i;
	QUERY_INFO_SIG *query_info = NULL;

	if (port_num % 2 == 0) {
		*buf_len = 4 + 20 + 16 + 6 + 2 + port_num * 2;
	} else {
		*buf_len = 4 + 20 + 16 + 6 + 2 + port_num * 2 + 1;
	}
	printf("buf_len in query constructor = %d\n", *buf_len);
	buf = calloc(1, *buf_len);
	if (NULL == buf) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	query_info = (QUERY_INFO_SIG *)buf;
	query_info->type_low = 1;
	query_info->type_high = 4;
	query_info->len = htons((short)(*buf_len - 4));
	memcpy(query_info->eid, eid, MSLEN);
	memcpy(query_info->ip, ip, IP6LEN);
	memcpy(query_info->mac, mac, MACLEN);
	//printf("query tag -1-\n");
	query_info->port_num = htons((short)port_num);

	for (i = 0; i < port_num; ++i)
	{
		*(buf + sizeof(QUERY_INFO_SIG) + i) = htons((short)(*(port_list + i)));
	}

	//printf("query tag -2-\n");
	/*if (port_num % 2 != 0) {
		*(buf + *buf_len - 1) = 0;
	} */

	//printf("buf[0] = %d\n", buf[0]);

	//printf("query tag -3-\n");
	i = 0;
	for (; i < *buf_len; ++i)
		printf("%d ", buf[i]);
	printf("\n");
	return buf;
}

uint8_t * entry_update_info_constructor(uint8_t *eid, uint16_t port_num, uint16_t *port_list, uint32_t *buf_len) {
	uint8_t *buf = NULL;
	int32_t i;
	ENTRY_UPDATE_INFO_SIG *entry_update_info = NULL;

	if (port_num % 2 == 0) {
		*buf_len = 4 + 20 + 4 + port_num * 2;
	} else {
		*buf_len = 4 + 20 + 4 + port_num * 2 + 1;
	}
	
	buf = calloc(1, *buf_len);
	if (NULL == buf) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	entry_update_info = (ENTRY_UPDATE_INFO_SIG *)buf;
	entry_update_info->type_low = 3;
	entry_update_info->type_high = 2;
	entry_update_info->len = htons((short)(*buf_len - 4));
	memcpy(entry_update_info->eid, eid, 20);
	entry_update_info->port_num = htons((short)port_num);

	for (i = 0; i < port_num; ++i)
	{
		*(buf + sizeof(ENTRY_UPDATE_INFO_SIG) + i) = htons((short)(*(port_list + i)));
	}

	if (port_num % 2 != 0) {
		*(buf + *buf_len - 1) = 0;
	} 

	return buf;
}


uint8_t * signalling_constructor(uint8_t type_low, uint8_t type_high, uint8_t *eid, uint32_t* buf_len) {
	SIGNALLING *sig = NULL;
	*buf_len = sizeof(SIGNALLING);

	sig = calloc(1, *buf_len);
	if (NULL == sig) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	sig->type_low = type_low;
	sig->type_high = type_high;
	sig->len = htons((short)20);
	memcpy(sig->eid, eid, 20);

	return (uint8_t *)sig;
}

uint8_t * switch_info_constructor(uint8_t *ip) {
	SWITCH_INFO_SIG *sig = NULL;

	sig = calloc(1, sizeof(SWITCH_INFO_SIG));
	if (NULL == sig) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	sig->type_low = 2;
	sig->type_high = 1;
	sig->len = htons((short)16);
	memcpy(sig->ip, ip, 16);

	return (uint8_t *)sig;
}

uint8_t * host_info_constructor(uint16_t port, uint8_t *mac, uint8_t *ip,  uint8_t *eid) {
	HOST_INFO_SIG *sig = NULL;

	sig = calloc(1, sizeof(HOST_INFO_SIG));
	if (NULL == sig) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	sig->type_low = 2;
	sig->type_high = 2;
	sig->len = htons((short)44);
	memcpy(sig->eid, eid, 20);
	sig->port = htons((short)port);
	memcpy(sig->mac, mac, 6);
	memcpy(sig->ip, ip, 16);

	return (uint8_t *)sig;
}

uint8_t * multicast_forward_info_constructor(uint8_t *eid, uint8_t *ip, uint16_t inport, uint16_t outport) {
	FORWARD_INFO_SIG *sig = NULL;

	sig = calloc(1, sizeof(FORWARD_INFO_SIG));
	if (NULL == sig) {
		printf("ERROR: calloc memory fail.\n");
		return NULL;
	} 

	sig->type_low = 2;
	sig->type_high = 3;
	sig->len = htons((short)40);
	memcpy(sig->eid, eid, 20);
	memcpy(sig->ip, ip, 16);
	sig->inport = htons((short)inport);
	sig->outport = htons((short)outport);

	return (uint8_t *)sig;
}