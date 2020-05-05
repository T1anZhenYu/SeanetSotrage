#ifndef __bbr_controller_h_
#define __bbr_controller_h_

#include "bbr_rtt_stats.h"
#include "bbr_bandwidth_sample.h"
#include "windowed_filter.h"
#include "bbr_feedback_adpater.h"
#include "bbr_common.h"
#include "bbr_header.h"
#include "common/cf_platform.h"

/*bbr״̬*/
enum {
	/*Startup phase of the connection*/
	STARTUP,
	/*After achieving the highest possible bandwidth during the startup, lower the pacing rate in order to drain the queue*/
	DRAIN,
	/*Cruising mode*/
	PROBE_BW,
	/*Temporarily slow down sending in order to empty the buffer and measure the real minimum RTT*/
	PROBE_RTT
};


/*BBR��������Ŀ*/
typedef struct
{
	double probe_bw_pacing_gain_offset;
	
	size_t initial_congestion_window;
	size_t min_congestion_window;
	size_t max_congestion_window;

	double probe_rtt_congestion_window_gain;

	/* The number of RTTs to stay in STARTUP mode.  Defaults to 3.*/
	int64_t num_startup_rtts;

	/* When true, pace at 1.5x and disable packet conservation in STARTUP.*/
	int slower_startup;

	/* If true, will not exit low gain mode until bytes_in_flight drops below BDP or it's time for high gain mode.*/
	int fully_drain_queue;

	/* If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.*/
	int probe_rtt_based_on_bdp;

}bbr_config_t;

/*bbr����*/

typedef struct
{
	bbr_rtt_stat_t					rtt_stat;						/*rtt�ӳ�ƽ������ģ��*/

	bbr_target_rate_constraint_t	constraints;
	
	int								mode;							/*bbrģʽ״̬*/
	bbr_bandwidth_sampler_t*		sampler;						/*��������ģ�ͣ����ڷ��ͺ�ACK����ά�Ƚ��м���*/
	int64_t							round_trip_count;
	uint16_t						current_round_trip_end;
	uint16_t						last_recv_packet_no;

	uint16_t						last_sent_packet;

	int32_t							default_bandwidth;
	windowed_filter_t				max_bandwidth;

	int64_t							min_rtt;
	int64_t							last_rtt;
	int64_t							min_rtt_timestamp;

	size_t							congestion_window;
	size_t							initial_congestion_window;
	size_t							max_congestion_window;
	size_t							min_congestion_window;

	int32_t							pacing_rate;
	double							pacing_gain;
	double							congestion_window_gain;
	double							congestion_window_gain_constant;

	double							rtt_variance_weight;

	int								cycle_current_offset;
	int64_t							last_cycle_start;
	int								probe_rtt_round_passed;
	int								is_at_full_bandwidth;

	int64_t							rounds_without_bandwidth_gain;
	int32_t							bandwidth_at_last_round;

	int64_t							exit_probe_rtt_at;
	int								app_limited_since_last_probe_rtt;
	int64_t							min_rtt_since_last_probe_rtt;
	int								exiting_quiescence;


	bbr_config_t					config;


}bbr_controller_t;


bbr_controller_t*					bbr_create(bbr_target_rate_constraint_t* co, int32_t starting_bandwidth);
void								bbr_destroy(bbr_controller_t* bbr);

bbr_network_ctrl_update_t			bbr_on_heartbeat(bbr_controller_t* bbr, int64_t now_ts);
bbr_network_ctrl_update_t			bbr_on_feedback(bbr_controller_t* bbr, bbr_feedback_t* feedback, uint32_t bandwidth);
void								bbr_on_send_packet(bbr_controller_t* bbr, bbr_packet_info_t* packet);
bbr_network_ctrl_update_t 			bbr_on_feedback(bbr_controller_t* bbr, bbr_feedback_t* feedback, uint32_t bandwidth);

#endif



