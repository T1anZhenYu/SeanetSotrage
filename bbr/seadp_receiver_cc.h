#ifndef __SEADP_RECEIVER_CC_h_
#define __SEADP_RECEIVER_CC_h_

#include "bbr_header.h"
#include "bbr_rtt_stats.h"
#include "bbr_bandwidth_sample.h"
#include "windowed_filter.h"
#include "bbr_feedback_adpater.h"
#include "bbr_common.h"
#include "bbr_controller.h"
#include "bbr_pacer.h"

//?????????

typedef int(*cc_send_cb)(void *,uint32_t packet_no);
typedef struct
{
	void* rs;	
	/*?????????????????*/
	uint32_t					last_bitrate_bps;
	//uint8_t						last_fraction_loss;
	uint32_t					last_rtt;

	int64_t						notify_ts;
	int64_t						last_req_cwnd_ts;

	bbr_network_ctrl_update_t	info;
	
	uint32_t					max_bitrate;
	uint32_t					min_bitrate;
	
	uint32_t					target_bitrate;

	uint32_t					cc_acked_bitrate;
	//?????????
	bbr_controller_t*			bbr;
	bbr_pacer_t*				pacer;
	bbr_fb_adapter_t			feedback;

	double						encoding_rate_ratio;
	cc_send_cb					send_cb;
}seadp_cc_t;

seadp_cc_t*	seadp_cc_create(void* rs, cc_send_cb send_cb,uint32_t max_bitrate, uint32_t min_bitrate, uint32_t start_bitrate);

void 	seadp_cc_destroy(seadp_cc_t* cc);

int		seadp_cc_add_packet(seadp_cc_t* cc, cc_req_packet_t* req_packet);

//void	seadp_cc_send_packet(seadp_cc_t* cc, uint16_t packet_number, uint32_t req_send_ts);

void	seadp_cc_on_feedback(seadp_cc_t* cc, data_packet_t* data_packet);

void	seadp_cc_heartbeat(seadp_cc_t* cc, int64_t now_ts);

size_t	seadp_cc_get_cwnd(seadp_cc_t* cc);

void	seadp_cc_set_bitrates(seadp_cc_t* cc, uint32_t min_bitrate, uint32_t start_bitrate, uint32_t max_bitrate);

void 	seadp_cc_remove_req_packet(seadp_cc_t* cc,uint32_t packet_number);

uint32_t cc_get_bw(seadp_cc_t* cc);

void    seadp_cc_choice(seadp_cc_t* cc,int chunksize);
#endif
