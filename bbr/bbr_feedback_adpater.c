#include "bbr_feedback_adpater.h"

#define k_history_cache_ms		5000
#define k_rate_window_size 1000
#define k_rate_scale 8000

//////////////////////////////////////////////////////////////////////////////////////////////
static void bbr_feedback_update_max_recv_packet_no(bbr_fb_adapter_t* adapter,uint16_t pkt_no);
//////////////////////////////////////////////////////////////////////////////////////////////

void bbr_feedback_adapter_init(bbr_fb_adapter_t* adapter)
{
	adapter->hist = sender_history_create(k_history_cache_ms);

	adapter->feedback.data_in_flight = 0;
	adapter->feedback.packet_number=0;
	adapter->feedback.max_recv_packet_no=0;

	rate_stat_init(&adapter->acked_bitrate, k_rate_window_size, k_rate_scale);
}

void bbr_feedback_adapter_destroy(bbr_fb_adapter_t* adapter)
{
	if (adapter->hist != NULL){
		sender_history_destroy(adapter->hist);
		adapter->hist = NULL;
	}

	rate_stat_destroy(&adapter->acked_bitrate);
}

void bbr_feedback_add_packet(bbr_fb_adapter_t* adapter, uint16_t pkt_no, size_t size)
{
	cc_req_packet_t packet;
	int64_t now_ts = GET_SYS_MS();

	packet.totalsize = size;
	packet.packet_no = pkt_no;
	packet.send_ts = now_ts;
	packet.rtt=0;
	sender_history_add(adapter->hist, &packet);

	sim_debug("bbr_feedback_add_packet pkt_no=%d, send_ts=%lld\n",pkt_no,now_ts);
}

size_t bbr_feedback_get_in_flight(bbr_fb_adapter_t* adapter)
{
	return sender_history_outstanding_bytes(adapter->hist);
}

int32_t bbr_feedback_get_birate(bbr_fb_adapter_t* adapter)
{
	return rate_stat_rate(&adapter->acked_bitrate, adapter->feedback.feedback_time);
}
//将反馈信息传入feedback模块，计算ack速率，计算RTT，计算带宽？
void 	bbr_feedback_on_feedback(bbr_fb_adapter_t* adapter,data_packet_t* packet){

	adapter->feedback.feedback_time=packet->recv_ts;
	adapter->feedback.packet_number=packet->packet_no;
	adapter->feedback.offset=packet->offset;
	adapter->feedback.size=packet->size;
	bbr_feedback_update_max_recv_packet_no(adapter,packet->packet_no);
//调用get函数找到对应的发送历史,返回最新的rtt
	adapter->feedback.last_rtt=sender_history_get(adapter->hist,packet);
	sim_debug("last_rtt:%d\n",adapter->feedback.last_rtt);
	
//计算ack速率
	rate_stat_update(&adapter->acked_bitrate,packet->size,packet->recv_ts);
	
}

void  bbr_feedback_delete_send_history(bbr_fb_adapter_t* adapter,uint16_t packet_number){
	return sender_history_remove(adapter->hist,packet_number);
}

static void bbr_feedback_update_max_recv_packet_no(bbr_fb_adapter_t* adapter,uint16_t pkt_no){
	if(pkt_no > adapter->feedback.max_recv_packet_no){
		adapter->feedback.max_recv_packet_no=pkt_no;
	}
	//sim_debug(" func: %s, line:%d, max_recv_packet_no:%d\n",__FUNCTION__,__LINE__,adapter->feedback.max_recv_packet_no);
}

uint16_t  bbr_get_max_recv_packet_no(bbr_feedback_t* feedback){
	//sim_debug(" func: %s, line:%d, max_recv_packet_no:%d\n",__FUNCTION__,__LINE__,feedback->max_recv_packet_no);
	return feedback->max_recv_packet_no;
}