#include "bbr_controller.h"
#include <rte_malloc.h>
#ifndef false
#define false 0
#endif

#ifndef true
#define true 1
#endif

#define kMinRttExpiry 10000
//////////////////////////////////////////////
static void 	bbr_enter_startup_mode(bbr_controller_t* bbr);
static bbr_network_ctrl_update_t bbr_create_rate_upate(bbr_controller_t* bbr, int64_t at_time);
static int 		bbr_check_if_min_rtt_expired(bbr_controller_t* bbr,int64_t now_ts);
static void 	bbr_update_gain_cycle_phase(bbr_controller_t* bbr, int64_t now_ts, size_t prior_in_flight);
static double 	bbr_get_pacing_gain(bbr_controller_t* bbr, int index);
static void 	bbr_enter_probe_bandwidth_mode(bbr_controller_t* bbr, int64_t now_ts);
static void 	bbr_check_if_full_bandwidth_reached(bbr_controller_t* bbr);
static void 	bbr_maybe_exit_startup_or_drain(bbr_controller_t* bbr, bbr_feedback_t* feedback);
static void 	bbr_maybe_enter_or_exit_probe_rtt(bbr_controller_t* bbr, bbr_feedback_t* feedback, int is_round_start, int min_rtt_expired);
static void 	bbr_calculate_pacing_rate(bbr_controller_t* bbr);
static void 	bbr_calculate_congestion_window(bbr_controller_t* bbr, size_t bytes_acked);
static int64_t  bbr_get_min_rtt(bbr_controller_t* bbr);
static size_t 	bbr_get_target_congestion_window(bbr_controller_t* bbr, double gain);
static int32_t  bbr_bandwidth_estimate(bbr_controller_t* bbr);
static int32_t  bbr_get_congestion_window(bbr_controller_t* bbr);
static size_t 	bbr_probe_rtt_congestion_window(bbr_controller_t* bbr);
static int32_t 	bbr_pacing_rate(bbr_controller_t* bbr);
static int 		bbr_update_round_trip_counter(bbr_controller_t* bbr, uint16_t max_recv_packet_no);
/////////////////////////////////////////////

static inline void bbr_set_default_config(bbr_config_t* config)
{
	config->probe_bw_pacing_gain_offset = 0.25;

	config->initial_congestion_window = kInitialCongestionWindowPackets * kDefaultTCPMSS;
	config->max_congestion_window = kDefaultMaxCongestionWindowPackets * kDefaultTCPMSS;
	config->min_congestion_window = kDefaultMinCongestionWindowPackets * kDefaultTCPMSS;

	config->probe_rtt_congestion_window_gain = 0.75;
	config->fully_drain_queue = false;
	config->num_startup_rtts = 3;
	config->probe_rtt_based_on_bdp = true;
}

bbr_controller_t* bbr_create(bbr_target_rate_constraint_t* co, int32_t starting_bandwidth)
{
	bbr_controller_t* bbr = (bbr_controller_t*)calloc(1, sizeof(bbr_controller_t));

	/*��ʼ��RTTͳ��ģ��*/
	bbr_rtt_init(&bbr->rtt_stat);

	/*��ʼ��BBRĬ�����ò���*/
	bbr_set_default_config(&bbr->config);

	//bbr->sampler = sampler_create();

	wnd_filter_init(&bbr->max_bandwidth, kBandwidthWindowSize, max_val_func);

	bbr->min_rtt = 0;
	bbr->last_rtt = 0;

	bbr->min_rtt_timestamp = 0;

	/*��ʼ��ӵ������*/
	bbr->congestion_window = bbr->config.initial_congestion_window;
	bbr->initial_congestion_window = bbr->config.initial_congestion_window;
	bbr->max_congestion_window = bbr->config.max_congestion_window;
	bbr->min_congestion_window = bbr->config.min_congestion_window;

	bbr->pacing_gain = 1;
	bbr->pacing_rate = 0;

	bbr->congestion_window_gain_constant = kProbeBWCongestionWindowGain;
	bbr->rtt_variance_weight = 0;
	bbr->cycle_current_offset = 0;
	bbr->last_cycle_start = 0;
	bbr->is_at_full_bandwidth = false;
	bbr->rounds_without_bandwidth_gain = 0;
	bbr->bandwidth_at_last_round = 0;
	bbr->exit_probe_rtt_at = -1;

	bbr->min_rtt_since_last_probe_rtt = -1;

	bbr->constraints = *co;
	bbr->default_bandwidth = starting_bandwidth;
	bbr->probe_rtt_round_passed = false;
	bbr->round_trip_count = 0;
	bbr->current_round_trip_end=0;
	bbr->last_recv_packet_no=-1;
	bbr_enter_startup_mode(bbr);

	return bbr;
}

void bbr_destroy(bbr_controller_t* bbr)
{
	if (bbr == NULL)
		return;

	if (bbr->sampler != NULL){
		sampler_destroy(bbr->sampler);
		bbr->sampler = NULL;
	}

	rte_free(bbr);
}

//��ʲô�õģ���
void	bbr_on_send_packet(bbr_controller_t* bbr, bbr_packet_info_t* packet){
	
	bbr->last_sent_packet = packet->seq;
	//����û����
	if (packet->data_in_flight == 0)
		bbr->exiting_quiescence = true;
}


/*bbr����STARTUPģʽ*/
static void bbr_enter_startup_mode(bbr_controller_t* bbr)
{
	bbr->mode = STARTUP;
	bbr->pacing_gain = kHighGain;
	bbr->congestion_window_gain = kHighGain;
}

bbr_network_ctrl_update_t bbr_on_heartbeat(bbr_controller_t* bbr, int64_t now_ts)
{
	return bbr_create_rate_upate(bbr, now_ts);
}

static bbr_network_ctrl_update_t bbr_create_rate_upate(bbr_controller_t* bbr, int64_t at_time){
	int32_t bandwidth, target_rate, pacing_rate;
	int64_t rtt;
	bbr_network_ctrl_update_t ret;


	ret.congestion_window = -1;
	if (at_time == -1)
		return ret;

	rtt = bbr_smoothed_rtt(&bbr->rtt_stat);

	/*����ӵ�����ƴ���*/
	ret.congestion_window = bbr_get_congestion_window(bbr);

	if (rtt <= 0)
		bandwidth = bbr->default_bandwidth;
	else
		bandwidth = ret.congestion_window / rtt;

	/*ȷ��pacing rate��target rate*/
	pacing_rate = bbr_pacing_rate(bbr);
	target_rate = bandwidth;
	////sim_debug(" func: %s, line:%d,pacing_rate:%dkBps,target_rate:%dkBps\n",__FUNCTION__,__LINE__,pacing_rate,target_rate);
	if (bbr->constraints.at_time > 0){
		if (bbr->constraints.max_rate > 0){
			target_rate = SU_MIN(target_rate, bbr->constraints.max_rate);
			pacing_rate = SU_MIN(pacing_rate, bbr->constraints.max_rate);
		}
		if (bbr->constraints.min_rate > 0){
			target_rate = SU_MAX(target_rate, bbr->constraints.min_rate);
			pacing_rate = SU_MAX(pacing_rate, bbr->constraints.min_rate);
		}
	}

	/*����target_rate��Ϣ*/
	ret.target_rate.at_time = at_time;
	ret.target_rate.bandwidth = bandwidth;
	ret.target_rate.rtt = SU_MAX(rtt, 8);
	ret.target_rate.bwe_period = rtt * kGainCycleLength;
	ret.target_rate.target_rate = target_rate;

	/*����pacer��Ϣ*/
	ret.pacer_config.at_time = at_time;
	ret.pacer_config.time_window = rtt > 20 ? (rtt / 4) : 5;
	ret.pacer_config.data_window = (size_t)(ret.pacer_config.time_window * pacing_rate);
	
	return ret;
}

bbr_network_ctrl_update_t bbr_on_feedback(bbr_controller_t* bbr, bbr_feedback_t* feedback, uint32_t bandwidth)
{
	int64_t	feedback_recv_time,last_rtt;
	int is_round_start = false, min_rtt_expired = false;
	int  now_ts;


	feedback_recv_time = feedback->feedback_time;
	/*û�з�����Ԫ,ֱ�ӷ���*/
	if (feedback->packet_number<= 0)
		return bbr_create_rate_upate(bbr, feedback->feedback_time);

	now_ts=GET_SYS_MS();
	/*ͳ��RTT*/
	last_rtt=feedback->last_rtt;
	if(bbr->min_rtt==0){
		bbr->min_rtt=last_rtt;
		bbr->min_rtt_timestamp=now_ts;
	}
	if(last_rtt<=bbr->min_rtt){
		bbr->min_rtt=last_rtt;
		bbr->min_rtt_timestamp=now_ts;
	}

	bbr_rtt_update(&bbr->rtt_stat, last_rtt,0);
	
	//�ж�min_rtt�Ƿ����
	min_rtt_expired=bbr_check_if_min_rtt_expired(bbr,now_ts);
	//�յ���ͬ����Ų�ȥ����rtt����
	if(bbr->last_recv_packet_no!=feedback->packet_number){
		bbr->last_recv_packet_no=feedback->packet_number;
		is_round_start = bbr_update_round_trip_counter(bbr,bbr_get_max_recv_packet_no(feedback));
	}
	
	 ////sim_debug(" func: %s, line:%d,bandwidth:%d, bandwidth_estimate:%d\n",__FUNCTION__,__LINE__,bandwidth, bbr_bandwidth_estimate(bbr));
	//��������,�ڿ�ʼ�׶Σ�
	// if ( bandwidth > bbr_bandwidth_estimate(bbr)){
       		    wnd_filter_update(&bbr->max_bandwidth, bandwidth,bbr->round_trip_count); 
       		    ////sim_debug(" func: %s, line:%d,update_bw, round_trip_count:%d\n",__FUNCTION__,__LINE__,bbr->round_trip_count);
       	 //}

		/*Handle logic specific to PROBE_BW mode*/
	if (bbr->mode == PROBE_BW)
		bbr_update_gain_cycle_phase(bbr, feedback_recv_time, feedback->data_in_flight);

	/* Handle logic specific to STARTUP and DRAIN modes */
	if (is_round_start && !bbr->is_at_full_bandwidth)
		bbr_check_if_full_bandwidth_reached(bbr);
	
	bbr_maybe_exit_startup_or_drain(bbr, feedback);

	/*Handle logic specific to PROBE_RTT,�ж��Ƿ�Ҫ����RTT���������RTT����*/
	bbr_maybe_enter_or_exit_probe_rtt(bbr, feedback, is_round_start, min_rtt_expired);

	bbr_calculate_pacing_rate(bbr);
	bbr_calculate_congestion_window(bbr, feedback->size);

	return bbr_create_rate_upate(bbr, feedback->feedback_time);
}

static int 	bbr_check_if_min_rtt_expired(bbr_controller_t* bbr,int64_t now_ts){

	int i, min_rtt_expired;
	

	min_rtt_expired = (bbr->min_rtt > 0 && now_ts > (bbr->min_rtt_timestamp + kMinRttExpiry)) ? true : false;
	////sim_debug(" func: %s, line:%d, min_rtt_expired :%d\n",__FUNCTION__,__LINE__,min_rtt_expired);
	return min_rtt_expired;
}

/*�������probe_bwģʽ�£����Խ���pacing_gain�����Ŵ��Դ���̽�����Ĵ���*/
static void bbr_update_gain_cycle_phase(bbr_controller_t* bbr, int64_t now_ts, size_t prior_in_flight)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	int gain_cycling;

	gain_cycling = (now_ts - bbr->last_cycle_start > bbr_get_min_rtt(bbr)) ? true : false;

	if (bbr->pacing_gain > 1.0  && prior_in_flight < bbr_get_target_congestion_window(bbr, bbr->pacing_gain))
		gain_cycling = false;

	if (bbr->pacing_gain < 1.0 && prior_in_flight < bbr_get_target_congestion_window(bbr, 1))
		gain_cycling = true;

	if (gain_cycling){
		bbr->cycle_current_offset = (bbr->cycle_current_offset + 1) % kGainCycleLength;
		bbr->last_cycle_start = now_ts;

		if (bbr->config.fully_drain_queue && bbr->pacing_gain < 1 && bbr_get_pacing_gain(bbr, bbr->cycle_current_offset) == 1
			&& prior_in_flight < bbr_get_target_congestion_window(bbr, 1))
			return;

		bbr->pacing_gain = bbr_get_pacing_gain(bbr, bbr->cycle_current_offset);
	}
}

static double bbr_get_pacing_gain(bbr_controller_t* bbr, int index)
{
	//sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	if (index == 0)
		return 1 + bbr->config.probe_bw_pacing_gain_offset;
	else if (index == 1)
		return 1 - bbr->config.probe_bw_pacing_gain_offset;
	else
		return 1;
}

static void bbr_enter_probe_bandwidth_mode(bbr_controller_t* bbr, int64_t now_ts)
{
	//sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	bbr->mode = PROBE_BW;
	bbr->congestion_window_gain = bbr->congestion_window_gain_constant;/*2.0f*/

	bbr->cycle_current_offset = rand() % (kGainCycleLength - 1);
	if (bbr->cycle_current_offset >= 1)
		bbr->cycle_current_offset += 1;

	bbr->last_cycle_start = now_ts;
	bbr->pacing_gain = bbr_get_pacing_gain(bbr, bbr->cycle_current_offset);
}

/*��STARTUP��DRAIN״̬�µĴ��������жϣ��жϵ�ǰ�����Ƿ�ﵽ��·��ߣ���ﵽ��ߣ�����Ϊ����������ʾ*/
static void bbr_check_if_full_bandwidth_reached(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	int32_t target;

	target = (int32_t)(bbr->bandwidth_at_last_round * kStartupGrowthTarget);
	if (target <= bbr_bandwidth_estimate(bbr)){ /*����������������Ԥ�ڵ�������˵�����������ʻ��пռ䣬������������ֱ������full bandwidth*/
		bbr->bandwidth_at_last_round = bbr_bandwidth_estimate(bbr);
		bbr->rounds_without_bandwidth_gain = 0;
	}
	else{
		bbr->rounds_without_bandwidth_gain++;

		if (bbr->rounds_without_bandwidth_gain >= bbr->config.num_startup_rtts) 
			bbr->is_at_full_bandwidth = true;
	}
}

static void bbr_maybe_exit_startup_or_drain(bbr_controller_t* bbr, bbr_feedback_t* feedback)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*�����startupģʽ������״̬�Ѿ��ǵ��˴��������������ӳٳ�������ֵ���л���DRAINģʽ*/
	if (bbr->mode == STARTUP && bbr->is_at_full_bandwidth){
		bbr->mode = DRAIN;
		bbr->pacing_gain = kDrainGain; // pace slowly
		bbr->congestion_window_gain = kHighGain;// maintain cwnd
	}
	//sim_debug(" func: %s, line:%d,bbr_mode:%d\n",__FUNCTION__,__LINE__,bbr->mode);

	/*�����drainģʽ���������ڴ��������С�ڵ�ǰ��ӵ�����ڣ�˵���д������࣬���Խ���probe_bwģʽ����������̽��*/
	if (bbr->mode == DRAIN && feedback->data_in_flight <= bbr_get_target_congestion_window(bbr, 1)){

		bbr_enter_probe_bandwidth_mode(bbr, feedback->feedback_time);
        }
}

/*�ж��Ƿ��������˳�PROBE_RTTģʽ*/
static void bbr_maybe_enter_or_exit_probe_rtt(bbr_controller_t* bbr, bbr_feedback_t* feedback, int is_round_start,int min_rtt_expired)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*���������min_rtt�����ҵ�ǰ����PROBE_RTTģʽ�£��л���PROBE_RTTģʽ��*/
	if (min_rtt_expired  && bbr->mode != PROBE_RTT){
		bbr->mode = PROBE_RTT;
		bbr->pacing_gain = 1;
		bbr->exit_probe_rtt_at = -1;
	}

	if (bbr->mode == PROBE_RTT){

		if (bbr->exit_probe_rtt_at < 0){
			/*���ڷ��͵��������䵽probe_rttģʽ�µ�ӵ����С��������СRTT�ɼ�,����200����*/
			if (feedback->data_in_flight < bbr_probe_rtt_congestion_window(bbr) + kMaxPacketSize){
				bbr->exit_probe_rtt_at = feedback->feedback_time + kProbeRttTimeMs;
				bbr->probe_rtt_round_passed = false;
			}
		}
		else{
			if (is_round_start)
				bbr->probe_rtt_round_passed = true;

			if (feedback->feedback_time >= bbr->exit_probe_rtt_at && bbr->probe_rtt_round_passed){
				/*probe_rtt��ϣ���¼�������Чʱ��*/
				bbr->min_rtt_timestamp = feedback->feedback_time;
				/*�л�BBR��ģʽ*/
				if (!bbr->is_at_full_bandwidth)
					bbr_enter_startup_mode(bbr);
				else
					bbr_enter_probe_bandwidth_mode(bbr, feedback->feedback_time);
			}
		}
	}
}


static void bbr_calculate_pacing_rate(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	int32_t target_rate;
	if (bbr_bandwidth_estimate(bbr) <= 0)
		return;

	target_rate = (int32_t)(bbr->pacing_gain * bbr_bandwidth_estimate(bbr));

	if (bbr->is_at_full_bandwidth){
		bbr->pacing_rate = bbr_get_congestion_window(bbr) / bbr_smoothed_rtt(&bbr->rtt_stat);
		bbr->pacing_rate = SU_MAX(target_rate, bbr->pacing_rate);
		return;
	}

	/*��ʼ�׶Σ��ó�ʼ����ӵ�����ڼ�������õ�����*/
	if (bbr->pacing_rate == 0 && bbr_min_rtt(&bbr->rtt_stat) > 0){
		bbr->pacing_rate = (int32_t)(bbr->initial_congestion_window / (bbr_min_rtt(&bbr->rtt_stat)));
		return;
	}


	bbr->pacing_rate = SU_MAX(bbr->pacing_rate, target_rate);
}

static void bbr_calculate_congestion_window(bbr_controller_t* bbr, size_t bytes_acked)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	size_t target_window;
	size_t tso_segs_goal = 0; //liucm
	int32_t	pacing_rate;//liucm

	/*PROBE_RTTģʽ�²��ı�ӵ������,һ���ǲ�����С����ģʽ����*/
	if (bbr->mode == PROBE_RTT)
		return;

	target_window = bbr_get_target_congestion_window(bbr, bbr->congestion_window_gain);

	if (bbr->rtt_variance_weight > 0 && bbr_bandwidth_estimate(bbr) > 0){
		target_window += (size_t)(bbr->rtt_variance_weight * bbr_mean_deviation(&bbr->rtt_stat) * bbr_bandwidth_estimate(bbr));
	}

	pacing_rate = bbr->pacing_rate;
        //razor_info("bbr_calculate_congestion_window pacing_rate:%u\n",pacing_rate);
	if(pacing_rate < 1200)
		tso_segs_goal = kDefaultTCPMSS;
	else if(pacing_rate < 24000)
		tso_segs_goal = 2*kDefaultTCPMSS;
	else
		tso_segs_goal = SU_MIN(pacing_rate,64000);
	target_window += 3*tso_segs_goal;

	if (bbr->is_at_full_bandwidth)
		bbr->congestion_window = SU_MIN(target_window, bbr->congestion_window + bytes_acked);
	else if (bbr->congestion_window < target_window)
		bbr->congestion_window = bbr->congestion_window + bytes_acked;

	bbr->congestion_window = SU_MAX(bbr->congestion_window, bbr->min_congestion_window);
	bbr->congestion_window = SU_MIN(bbr->congestion_window, bbr->max_congestion_window);
}

static int64_t bbr_get_min_rtt(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	if (bbr->min_rtt == 0)
		return bbr_initial_rtt_us(&bbr->rtt_stat) / 1000;
	else
		return bbr->min_rtt;
}

/*����BDP�ķ��ʹ���С*/
static size_t bbr_get_target_congestion_window(bbr_controller_t* bbr, double gain)
{
	size_t bdp, congestion_window;
	
	bdp = (int32_t)(bbr_get_min_rtt(bbr) * bbr_bandwidth_estimate(bbr));
	//sim_debug(" func: %s, line:%d,bdp:%d bytes\n",__FUNCTION__,__LINE__,bdp);
	congestion_window = (size_t)(gain * bdp);
	
	if (congestion_window <= 0)
		congestion_window = (size_t)(gain * bbr->initial_congestion_window);


	return SU_MAX(congestion_window, bbr->min_congestion_window);
}

static int32_t bbr_bandwidth_estimate(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	return (int32_t)wnd_filter_best(&bbr->max_bandwidth);
}

/*���bbr��ǰ��ӵ�����ڴ�С*/
static int32_t bbr_get_congestion_window(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*�����������Сrttģʽ�£���Ҫȡ��С�Ĳ�������*/
	if (bbr->mode == PROBE_RTT)
		return bbr_probe_rtt_congestion_window(bbr);

	return bbr->congestion_window;
}

/*��ȡ��probe_rttģʽ�µ�ӵ�����ڴ�С*/
static size_t bbr_probe_rtt_congestion_window(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	if (bbr->config.probe_rtt_based_on_bdp)
		return bbr_get_target_congestion_window(bbr, bbr->config.probe_rtt_congestion_window_gain);
	else
		return bbr->min_congestion_window;
}


static int32_t bbr_pacing_rate(bbr_controller_t* bbr)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	if (bbr->pacing_rate == 0)
		return (int32_t)(kHighGain * bbr->initial_congestion_window / bbr_get_min_rtt(bbr));
	else
		return bbr->pacing_rate;
}

/*�ж��Ƿ����һ��round trip���ڣ�����ǣ����м�����+1����������һ�ڵ�round trip��λ����Ϣ*/
static int bbr_update_round_trip_counter(bbr_controller_t* bbr, uint16_t max_recv_packet_no)
{
	////sim_debug(" func: %s, line:%d,bbr->round_trip_count:%d\n",__FUNCTION__,__LINE__,bbr->round_trip_count);
	if (max_recv_packet_no >= bbr->current_round_trip_end){
		bbr->round_trip_count++;
		bbr->current_round_trip_end = bbr->last_sent_packet;
		return true;
	}
	else
		return false;
}