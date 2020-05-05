#ifndef __bbr_feedback_adpater_h_
#define __bbr_feedback_adpater_h_

#include "sender_history.h"
#include "rate_stat.h"
#include "common/cf_platform.h"
#include "pacer_queue.h"
#include "bbr_header.h"
#include "estimator_common.h"


typedef struct
{
	int64_t					feedback_time;

	size_t					data_in_flight;

	uint16_t 				packet_number;
	size_t 					offset;
	size_t 					size;
	int64_t					last_rtt;
	uint16_t       			max_recv_packet_no;
}bbr_feedback_t;

typedef struct
{
	sender_history_t*		hist;
	bbr_feedback_t			feedback;
	rate_stat_t				acked_bitrate;
}bbr_fb_adapter_t;

void						bbr_feedback_adapter_init(bbr_fb_adapter_t* adapter);
void						bbr_feedback_adapter_destroy(bbr_fb_adapter_t* adapter);
void 						bbr_feedback_add_packet(bbr_fb_adapter_t* adapter,uint16_t pkt_no, size_t size);
size_t 						bbr_feedback_get_in_flight(bbr_fb_adapter_t* adapter);
int32_t 					bbr_feedback_get_birate(bbr_fb_adapter_t* adapter);
void 						bbr_feedback_on_feedback(bbr_fb_adapter_t* adapter,data_packet_t* packet);
int32_t    					bbr_feedback_get_birate(bbr_fb_adapter_t* adapter);
void  						bbr_feedback_delete_send_history(bbr_fb_adapter_t* adapter,uint16_t packet_number);
uint16_t  					bbr_get_max_recv_packet_no(bbr_feedback_t* feedback);
#endif


