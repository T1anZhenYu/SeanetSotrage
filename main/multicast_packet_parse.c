#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <inttypes.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "multicast_ae.h"
#include "mobile_app.h"
#include "seaep_loop.h"
#include "init.h"

/* MARK-3-2019/11/12 */
int cancel()
{
	return 0;
}

int packet_parser(uint8_t *raw_pkt, uint32_t len, struct local_resource *lr, struct app_lcore_params *conf) {
	uint8_t next_hdr, sig_type_low, sig_type_high,ttl;
	uint8_t *sig = NULL, *mac = NULL, *ip = NULL, *eid = NULL;
	uint16_t type, src_port, dst_port, port;
	int ret = AE_OK;
	MAC_HEADER *mac_hdr = (MAC_HEADER *)raw_pkt;

	type = ntohs(mac_hdr->type);
	//printf("type: %x\n", type);
	mac = mac_hdr->src_mac;
	if (type != 0x86dd) {
		printf("This packet received is not a IPv6 packet\n");
		return AE_ERROR;
	}

	IPV6_HEADER *ip_hdr = (IPV6_HEADER *)(raw_pkt + sizeof(MAC_HEADER));
	ip = ip_hdr->src_ip;
    //printf("src_ip:%x\n",ip_hdr->src_ip);
    //printf("dst_ip:%x\n",ip_hdr->dst_ip);
	printf("IP = ");
	int ipi = 0;
	for (; ipi < IP6LEN; ipi++)
	{
		printf("%x ", ip[ipi]);
	}
	// printf("\ndst IP = ");
	// ipi = 0;
	// for (; ipi < IP6LEN; ipi++)
	// {
	// 	printf("%x ", ip_hdr->dst_ip[ipi]);
	// }
	printf("\nMAC = ");
	ipi = 0;
	for (; ipi < MACLEN; ipi++)
	{
		printf("%x ", mac[ipi]);
	}
	printf("\n");

	next_hdr = ip_hdr->next_header;
	//printf("next_hdr: %x\n", next_hdr);

    //ttl=ip_hdr->ttl;
	//printf("ttl: %d\n", ttl);

	if (next_hdr != 0x11) {
		// packet which is not UDP 
		return AE_ERROR;
	} else {
		UDP_HEADER *udp_hdr = (UDP_HEADER *)(raw_pkt + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER));
		
		src_port = ntohs(udp_hdr->src_port);
		dst_port = ntohs(udp_hdr->dst_port);
		//printf("src_port: %d, dst_port: %d \n", src_port, dst_port);

		if (src_port != 50000 || dst_port != 60000) {
			// packet which is not multicast signalling 
			return AE_ERROR;
		} else {
			sig = (uint8_t *)(raw_pkt + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER));
			sig_type_low = *sig;
			sig_type_high = *(sig + 1);
			//printf("packet_parser tag - 1 - \n");
			printf("sig_type_low = %d\n", sig_type_low);
			switch (sig_type_low) {
				case 1:
					eid = ((SIGNALLING *)sig)->eid;
					ipi = 0;
					printf("EID = ");
					for (; ipi < MSLEN; ++ipi)
					{
						printf("%x ", eid[ipi]);
					}
					printf("\n");
			        //printf("sig_type_low tag - 1 - \n");
					switch (sig_type_high) {
						case 1:
							//printf("join handle tag - 1 - \n");
							ret = join_sig_handler(eid, mac, ip, raw_pkt, len, lr, conf);
							CHECK_INT_RETURN(ret, "Handle join packet fail!");
							printf("Handle join packet succeed!\n");
							break;
						case 6:
							//printf("quit handle tag - 1 - \n");
							ret = quit_sig_handler(eid, mac, ip, lr, conf);
							//printf("quit handle tag - 2 - \n");
							CHECK_INT_RETURN(ret, "Handle quit packet fail!");
							//printf("quit handle tag - 3 - \n");
							break;
						case 3:
							port = ntohs(((SIGNALLING *)sig)->len);
							//printf("prune_sig_handler tag - 1 - \n");
							ret = prune_sig_handler(eid, port, lr, conf);
							//printf("prune_sig_handler  tag - 2 - \n");
							CHECK_INT_RETURN(ret, "Handle prune packet fail!");
							break;
						case 5:
							ret = reply_sig_handler(eid, mac, ip);
							CHECK_INT_RETURN(ret, "Handle reply packet fail!");
							break;
						default:
							error_handler();
							break;
					}
				break;
				printf("sig_type_low = %d\n", sig_type_low);
				case 2:
			        //printf("sig_type_low tag - 20 - \n");
			        printf("sig_type_high = %d\n", sig_type_high);
					switch (sig_type_high) {
						case 1:
							ret = switch_info_sig_handler(sig, lr);
							CHECK_INT_RETURN(ret, "Handle switch info packet fail!");
							break;
						case 2:
							ret = host_info_sig_handler(sig, lr, conf);
							CHECK_INT_RETURN(ret, "Handle host info packet fail!");
							break;
						case 3:
			                //printf("sig_type_high tag - 23 - \n");
							ret = fwd_info_sig_handler(sig);
							CHECK_INT_RETURN(ret, "Handle forward info packet fail!");
			                //printf("sig_type_high tag - 23 -0 \n");

							break;
						default:
							error_handler();
							break;
					}
					break;
				default:
					error_handler();
					break;
			}
		}
	}

	return ret;
}

int join_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, uint8_t *raw_pkt, uint32_t raw_pkt_len, struct local_resource *lr, struct app_lcore_params *conf) {
	printf("this is join handler!\n");
	int ret = AE_OK;

	/* Whether this multicast eid is already exist. */
	if (!is_multicast_in_forward_info_base(eid)) {
		printf("JOIN CASE 1 : no such a fwd info with this EID.\n");
		/* Send raw packet to fe. */
		//ret = send_packet(raw_pkt, raw_pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(raw_pkt, raw_pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("Send packet succeed!\n");
	} else {
		/* Construct join info and send to fe. */
		printf("JOIN CASE 2 : already have such a fwd info with this EID.\n");
		uint16_t port_num = 0; 
		uint32_t pkt_len = 0, sig_len = 0;
		uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
		uint8_t *join_sig = NULL, *pkt = NULL;
		uint16_t *port_list = get_outports_from_forward_info_base(eid, &port_num);
		CHECK_POINTER_RETURN(port_list, "Get output ports fail!");
		printf("Get output ports succeed\n");

		join_sig = join_info_constructor(eid, mac, ip, port_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(join_sig, "Construct join signalling fail!");
		printf("Construct join signalling succeed\n");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, join_sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");
		printf("Construct packet succeed\n");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("Send packet succeed\n");

		free(pkt);
	}

	return ret;
	printf("ret:%d\n",ret);
}

int quit_sig_query_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, struct local_resource *lr, struct app_lcore_params *conf) {
	printf("A host starts to quit~\n");
	int ret = AE_OK;
	uint32_t host_num = 0, pkt_len = 0, sig_len = 0; 
	uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
	uint8_t *sig = NULL, *pkt = NULL;
	uint16_t *port_list = NULL, outport = 0, outport_num = 0;
	FORWARD_INFO *fwd_info = NULL;
	EDGE_SWITCH_INFO *edge_switch_info = NULL;
	PORT_INFO *port_info = NULL;
	HOST_INFO *host_info = NULL;

	edge_switch_info = get_edge_switch_info_from_host_info_base(eid);
	CHECK_POINTER_RETURN(edge_switch_info, "Host info base doesn't have this multicast!");
	printf("Host info base have this multicast~\n");

	host_info = get_host_info_from_edge_switch_info(edge_switch_info, mac, ip);
	CHECK_POINTER_RETURN(host_info, "Host info base doesn't have this host member!");
	printf("Host info base have this host member~\n");

	port_info = get_port_info_from_edge_switch_info(edge_switch_info, host_info);
	CHECK_POINTER_RETURN(port_info, "Host info base doesn't have this port!");
	printf("Host info base have this port~\n");
	outport = port_info->port;
	
	ret = port_info_delete_host(port_info, host_info);
	CHECK_INT_RETURN(ret, "Delete host info fail!");
	printf("Deleted host info~\n");

	if (port_info->hosts_num != 0) {
		/* Host list is not empty. */
		return AE_OK;
	} 
	
	/* Host list is empty. */
	/* Info base delete port. */
	//ret = edge_switch_info_delete_port(edge_switch_info, port_info);
	ret = host_info_base_delete_port(eid, port_info);
	CHECK_INT_RETURN(ret, "Host info base delete port fail!");
	printf("Host info base delete port succefully~\n");

	/* MARK-1-2019/11/12: Add a function "host_info_base_is_empty" in multicast_info_base.c */
	if (host_info_base_is_empty()) {
		printf("Host info base is empty!\n");
		lr->edge_flag = FALSE;
		//pthread_cancel(lr->member_query_thread);
	}

	fwd_info = get_forward_info_from_forward_info_base(eid);
	CHECK_POINTER_RETURN(fwd_info, "Forward info base doesn't have this multicast!");

	/* MARK-2-2019/11/12: Add a function "forward_info_base_delete_outport" in multicast_info_base.c */
	ret = forward_info_base_delete_outport(eid, outport);
	CHECK_INT_RETURN(ret, "Forward info base delete outport fail!");
	printf("Forward info base delete port succefully~\n");

	//if (fwd_info->outport.port_num != 0) {
	port_list = get_outports_from_forward_info_base(eid, &outport_num);
	CHECK_POINTER_RETURN(port_list, "Get output ports fail!");
	if (0 != outport_num) {
		/* Port list is not empty. */
		/* Construct multicast farward info and send to fe. */
		sig = entry_update_info_constructor(eid, outport_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_mc_query(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("send to quit tag1\n");

		free(pkt);
	} else {
		/* Port list is empty. */
		//if (edge_switch_info->port_num != 0) {
		if (0 != get_outport_num_from_host_info_base(eid)) {
			printf("ERROR: Forward info base and host info base are inconsistent.\n");
			return AE_ERROR;
		}

		/* Log off to the name resolution system. */
		cancel();

		/* Construct multicast farward info and send to fe. */
		/*port_list = get_outports_from_forward_info_base(eid, &outport_num);
		CHECK_POINTER_RETURN(port_list, "Get output ports fail!");
		printf("Get outport ports~\n");*/

		sig = entry_update_info_constructor(eid, outport_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");
		printf("Construct entry update signalling~\n");
		printf("sig_len = %d\n", sig_len);

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");
		printf("Construct packet~tag1\n");
		printf("pkt_len = %d\n", pkt_len);
		int i = 0;
		for (; i < pkt_len; ++i)
		{
			printf("%x ", pkt[i]);
		}
		printf("\n");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_mc_query(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("send to quit tag2\n");
		printf("Send packet~\n");
		free(pkt);

		sleep(5);

		/* Construct prune packet and send to fe. */
		sig = signalling_constructor((uint8_t)1, (uint8_t)6, eid, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct prune signalling fail!");
		printf("Construct prune signalling~\n");
		printf("sig_len = %d\n", sig_len);

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, fwd_info->pre_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");
		printf("Construct packet~tag2\n");
		printf("pkt_len = %d\n", pkt_len);
		i = 0;
		for (; i < pkt_len; ++i)
		{
			printf("%x ", pkt[i]);
		}
		printf("\n");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_mc_query(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("send to quit tag3\n");
		printf("Send packet~\n");
		free(pkt);

		sleep(5);

		/* Clear info about this multicast. */
		ret = clear_multicast_info(eid); 
		CHECK_INT_RETURN(ret, "Clear multicast info fail!");
	}

	return AE_OK;
}

int quit_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip, struct local_resource *lr, struct app_lcore_params *conf) {
	printf("A host starts to quit~\n");
	int ret = AE_OK;
	uint32_t host_num = 0, pkt_len = 0, sig_len = 0; 
	uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
	uint8_t *sig = NULL, *pkt = NULL;
	uint16_t *port_list = NULL, outport = 0, outport_num = 0;
	FORWARD_INFO *fwd_info = NULL;
	EDGE_SWITCH_INFO *edge_switch_info = NULL;
	PORT_INFO *port_info = NULL;
	HOST_INFO *host_info = NULL;

	edge_switch_info = get_edge_switch_info_from_host_info_base(eid);
	CHECK_POINTER_RETURN(edge_switch_info, "Host info base doesn't have this multicast!");
	printf("Host info base have this multicast~\n");

	host_info = get_host_info_from_edge_switch_info(edge_switch_info, mac, ip);
	CHECK_POINTER_RETURN(host_info, "Host info base doesn't have this host member!");
	printf("Host info base have this host member~\n");

	port_info = get_port_info_from_edge_switch_info(edge_switch_info, host_info);
	CHECK_POINTER_RETURN(port_info, "Host info base doesn't have this port!");
	printf("Host info base have this port~\n");
	outport = port_info->port;
	
	ret = port_info_delete_host(port_info, host_info);
	CHECK_INT_RETURN(ret, "Delete host info fail!");
	printf("Deleted host info~\n");

	if (port_info->hosts_num != 0) {
		/* Host list is not empty. */
		return AE_OK;
	} 
	
	/* Host list is empty. */
	/* Info base delete port. */
	//ret = edge_switch_info_delete_port(edge_switch_info, port_info);
	ret = host_info_base_delete_port(eid, port_info);
	CHECK_INT_RETURN(ret, "Host info base delete port fail!");
	printf("Host info base delete port succefully~\n");

	/* MARK-1-2019/11/12: Add a function "host_info_base_is_empty" in multicast_info_base.c */
	if (host_info_base_is_empty()) {
		printf("Host info base is empty!\n");
		lr->edge_flag = FALSE;
		//pthread_cancel(lr->member_query_thread);
	}

	fwd_info = get_forward_info_from_forward_info_base(eid);
	CHECK_POINTER_RETURN(fwd_info, "Forward info base doesn't have this multicast!");

	/* MARK-2-2019/11/12: Add a function "forward_info_base_delete_outport" in multicast_info_base.c */
	ret = forward_info_base_delete_outport(eid, outport);
	CHECK_INT_RETURN(ret, "Forward info base delete outport fail!");
	printf("Forward info base delete port succefully~\n");

	//if (fwd_info->outport.port_num != 0) {
	port_list = get_outports_from_forward_info_base(eid, &outport_num);
	if (0 != outport_num) {
		/* Port list is not empty. */
		/* Construct multicast farward info and send to fe. */
		sig = entry_update_info_constructor(eid, outport_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");

		free(pkt);
	} else {
		/* Port list is empty. */
		//if (edge_switch_info->port_num != 0) {
		if (0 != get_outport_num_from_host_info_base(eid)) {
			printf("ERROR: Forward info base and host info base are inconsistent.\n");
			return AE_ERROR;
		}

		/* Log off to the name resolution system. */
		cancel();

		/* Construct multicast farward info and send to fe. */
		port_list = get_outports_from_forward_info_base(eid, &outport_num);
		CHECK_POINTER_RETURN(port_list, "Get output ports fail!");
		printf("Get outport ports~\n");

		sig = entry_update_info_constructor(eid, outport_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");
		printf("Construct entry update signalling~\n");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");
		printf("Construct packet~\n");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("Construct packet~\n");
		free(pkt);

		/* Construct prune packet and send to fe. */
		sig = signalling_constructor((uint8_t)1, (uint8_t)6, eid, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct prune signalling fail!");
		printf("Construct prune signalling~\n");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, fwd_info->pre_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");
		printf("Construct packet~\n");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");
		printf("Send packet~\n");
		free(pkt);

		/* Clear info about this multicast. */
		ret = clear_multicast_info(eid); 
		CHECK_INT_RETURN(ret, "Clear multicast info fail!");
	}

	return AE_OK;
}

int prune_sig_handler(uint8_t *eid, uint16_t port, struct local_resource *lr, struct app_lcore_params *conf) {
	//printf("HERE I AM~ -1-\n");
	int ret = AE_OK;
	uint32_t pkt_len = 0, sig_len = 0; 
	uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
	uint8_t *sig = calloc(1, BUFFLEN), *pkt = calloc(1, BUFFLEN);
	uint16_t *port_list = NULL, port_num = 0;
	FORWARD_INFO *fwd_info = NULL;

	fwd_info = get_forward_info_from_forward_info_base(eid);
	CHECK_POINTER_RETURN(fwd_info, "Forward info base doesn't have this multicast!");
	//printf("HERE I AM~ -2-\n");

	/* Delete output port in the MFB. */
	ret = forward_info_delete_outport(fwd_info, port);
	CHECK_INT_RETURN(ret, "Forward info base delete outport fail!");
	//printf("HERE I AM~ -3-\n");

	if (fwd_info->outport.outport_num != 0) {
		//printf("HERE I AM~ -4- not empty\n");
		/* Port list is not empty. */

		/* Construct multicast farward info and send to fe. */
		port_list = get_outports_from_forward_info(fwd_info, &port_num);
		CHECK_POINTER_RETURN(port_list, "Get output ports fail!");

		sig = entry_update_info_constructor(eid, port_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");
		printf("Construct got a port : %d\n", port_list[0]);

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");

		free(pkt);
	} else {
		//printf("HERE I AM~ -5- empty\n");
		/* Port list is empty. */
		if (fwd_info->outport.outport_num != 0) {
			printf("ERROR: Forward info base and host info base are inconsistent.\n");
			return AE_ERROR;
		}

		/* Log off to the name resolution system. */
		ret = cancel();
		CHECK_INT_RETURN(ret, "Cancel fail!");

		/* Construct multicast farward info and send to fe. */
		port_list = get_outports_from_forward_info(fwd_info, &port_num);
		CHECK_POINTER_RETURN(port_list, "Get output ports fail!");

		sig = entry_update_info_constructor(eid, port_num, port_list, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct entry update signalling fail!");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");

		free(pkt);

		/* Construct prune packet and send to fe. */
		sig = signalling_constructor((uint8_t)1, (uint8_t)6, eid, &sig_len);
		CHECK_POINTER_RETURN(sig, "Construct prune signalling fail!");

		pkt = udp_packet_constructor(src_mac, dst_mac, src_ip, fwd_info->pre_ip, sig, sig_len, &pkt_len);
		CHECK_POINTER_RETURN(pkt, "Construct packet fail!");

		//ret = send_packet(pkt, pkt_len, lr);
		//20191211
		ret = sendtotxt_multicast(pkt, pkt_len, conf->send_ring);
		CHECK_INT_RETURN(ret, "Send packet fail!");

		free(pkt);

		/* Clear info about this multicast. */
		ret = clear_multicast_info(eid); 
		CHECK_INT_RETURN(ret, "Clear multicast info fail!");
	}

	return AE_OK;
}

int reply_sig_handler(uint8_t *eid, uint8_t *mac, uint8_t *ip) {
	HOST_INFO *host_info = NULL;

	/* Whether this multicast eid is already exist. */
	if (is_multicast_in_forward_info_base(eid) == FALSE) {
		printf("ERROR: AE don't have this multicast.");
		return AE_ERROR;
	} else {
		/* Clear the host's reply counter. */
		host_info = get_host_info_from_host_info_base(eid, mac, ip);
		CHECK_POINTER_RETURN(host_info, "Host info base doesn't have this host member!");

		/* Clear the host's reply counter. */
		host_info->count = 0;
		printf("host's count return to zero~\n");

		return AE_OK;
	}
}

int switch_info_sig_handler(uint8_t *sig, struct local_resource *lr) {
	uint8_t *ip = ((SWITCH_INFO_SIG *)sig)->ip;
	memcpy(lr->switch_ip, ip, 16);

	return AE_OK;
}

int host_info_sig_handler(uint8_t *pkt, struct local_resource *lr, struct app_lcore_params *conf) {
	int ret = AE_OK;
	HOST_INFO_SIG *sig = (HOST_INFO_SIG *)pkt;
	uint8_t *eid = sig->eid;
	int ipi = 0;
	printf("EID = ");
	for (; ipi < MSLEN; ++ipi)
	{
		printf("%x ", eid[ipi]);
	}
	printf("\n");
	uint16_t port = ntohs(sig->port);
	printf("OUTPORT = %x\n", port);
	uint8_t *mac = sig->mac;
	uint8_t *ip = sig->ip;

	printf("edge switch server num = %d\n", edge_switch_info_base.server_num);
	ret = host_info_base_add_host(eid, port, mac, ip);
	CHECK_INT_RETURN(ret, "Host info base add host fail!");
	// printf("edge switch ports num = %d\n", edge_switch_info_base.edge_switch_info->ports_num);

	// int i = 0;
	// printf("edge switch eid = ");
	// for (; i < MSLEN; ++i)
	// {
	// 	printf("%d ", edge_switch_info_base.edge_switch_info->multicast_service_eid[i]);
	// }
	// printf("\n");
	if (!lr->edge_flag) {
		printf("need to do member_query~\n");
		lr->edge_flag = TRUE;
		//ret = start_member_query(lr, conf);
		//printf("2019/12/17 tag-1\n");
		struct app_lcore_params *conf;
		conf = &lcore_conf[app_conf.lcore_configuration.multicast];
  		//seaep_init(conf->recv_ring, "2400:dd01:1037:101:192:168:101:16",
        //     "2400:dd01:1037:101:192:168:101:241", 1, 50);
		struct member_query_starter *mq_starter = calloc(1, sizeof(struct member_query_starter));
		mq_starter->is_multicast = TRUE;
		mq_starter->start = TRUE;
		// void* tst = NULL;
		// snprintf((char *)tst, sizeof("helloworld"), "%s", "helloworld");
		//printf("2019/12/17 tag-2\n");
		int checking = rte_ring_enqueue(conf->recv_ring, mq_starter);
		//printf("2019/12/17 tag-3\n");
		if (checking == 0)
		{
			printf("send to ring for member query succeed\n");
		}
		else
			printf("send to ring for member query failed\n");

		CHECK_INT_RETURN(ret, "Start member query therad fail!");
	}
	//printf("safely exit host_info_sig_handler\n");
	return ret;
}

int fwd_info_sig_handler(uint8_t *pkt) {
	int ret = AE_OK;
	FORWARD_INFO_SIG *sig = (FORWARD_INFO_SIG *)pkt;
	uint8_t *eid = sig->eid;
	int ipi = 0;
	printf("EID = ");
	for (; ipi < MSLEN; ++ipi)
	{
		printf("%x ", eid[ipi]);
	}
	printf("\n");
	uint8_t *pre_ip = sig->ip;
	uint16_t inport = ntohs(sig->inport);
	uint16_t outport = ntohs(sig->outport);
	printf("OUTPORT = %x\n", outport);
	printf("FWD ADDING (outport): %x\n", outport);
	
	/* Whether this multicast eid is already exist. */
	FORWARD_INFO *fwd_info = get_forward_info_from_forward_info_base(eid);
	if (NULL == fwd_info) {
		/* AE don't have this multicast, add multicast forward info. */
		ret = forward_info_base_add_multicast(eid, pre_ip, inport, outport);
		CHECK_INT_RETURN(ret, "Forward info base add multicast fail!");
		printf("Forward info base add multicast succeed!\n");
		printf("fw num = %d\n", forward_info_base.forward_num);
		printf("fw inport = %d\n", forward_info_base.forward_info->inport);
		int i = 0;
		printf("fw eid = ");
		for (; i < MSLEN; ++i)
		{
			printf("%d ", forward_info_base.forward_info->multicast_service_eid[i]);
		}
		i = 0;
		printf("\n");
		printf("fw ip = ");
		for (; i < IP6LEN; ++i)
		{
			printf("%d ", forward_info_base.forward_info->pre_ip[i]);
		}
		i = 0;
		printf("\n");
		printf("fw outport num = %d\n", forward_info_base.forward_info->outport.outport_num);
		printf("fw outport = ");
		for (; i < forward_info_base.forward_info->outport.outport_num; ++i)
		{
			printf("%02X ", forward_info_base.forward_info->outport.outport_index[i]);
		}
		printf("\n");
	} else {
		/* AE have this multicast, add multicast new output port info. */
		ret = forward_info_add_outport(fwd_info, outport);
		//ret = forward_info_base_add_multicast(fwd_info->multicast_service_eid, fwd_info->pre_ip, fwd_info->inport, outport);
		CHECK_INT_RETURN(ret, "Forward info add outport fail!");
		printf("Forward info base add outport succeed!\n");

	}
	
	return ret;
}

int error_handler() {
	return AE_ERROR;
}

int clear_multicast_info(uint8_t *eid) {
	// sleep(2);
	//printf("clear tag here - 1 -\n");
	int ret = AE_OK;
	ret = forward_info_base_delete_multicast(eid);
	CHECK_INT_RETURN(ret, "Forward info base delete multicast fail!");
	ret = host_info_base_delete_multicast(eid);
	CHECK_INT_RETURN(ret, "host info base delete multicast fail!");

	return ret;
}

/*int start_member_query(struct local_resource_app_lcore_params *lr_conf) {
	int ret = AE_OK;

	ret = pthread_create(&(lr->member_query_thread), NULL, member_query, lr_conf);
	CHECK_INT_RETURN(ret, "Creat member query therad fail");
	
	return ret;
}*/
