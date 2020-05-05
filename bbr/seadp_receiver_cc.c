#include "seadp_receiver_cc.h"
#include <rte_malloc.h>

#define k_bbr_heartbeat_timer 1000
#define kDefaultACKBITRATE 1000
#define kMaxCwnd 100000

static void seadp_cc_on_network_invalidation(seadp_cc_t* cc);
static void seadp_cc_send_packet(seadp_cc_t* cc, uint16_t packet_no, size_t size);

static int do_send_packet(void* handler, uint16_t packet_no,size_t size)
{
    seadp_cc_t* cc=handler;
    if(cc->send_cb){
        int res=cc->send_cb(cc->rs,packet_no);
        if(res==0){
            /*将发送记录送入拥塞对象中估算*/
            seadp_cc_send_packet(cc, packet_no, size);
            cc->bbr->last_sent_packet=packet_no;
        }
        else{
            return -1;
        }
    }

    return 0;
}


seadp_cc_t* seadp_cc_create(void* rs, cc_send_cb send_cb,uint32_t max_bitrate, uint32_t min_bitrate, uint32_t start_bitrate){

	seadp_cc_t* cc=(seadp_cc_t*)calloc(1,sizeof(seadp_cc_t));
	cc->rs=rs;
	bbr_target_rate_constraint_t co;
	cc->send_cb=send_cb;
	cc->last_bitrate_bps=0;
	cc->last_rtt=0;
	cc->notify_ts=-1;
	cc->last_req_cwnd_ts=-1;
	cc->cc_acked_bitrate=-1;
	cc->info.congestion_window=kInitialCongestionWindowPackets * kDefaultTCPMSS;
	cc->info.data_in_flight=0;
	if (cc->bbr == NULL){
		co.at_time = GET_SYS_MS();
		co.min_rate = min_bitrate / 8000;
		co.max_rate = max_bitrate / 8000;

		cc->bbr = bbr_create(&co, start_bitrate / 8000);
	}

	cc->pacer=bbr_pacer_create(do_send_packet,300);

	seadp_cc_set_bitrates(cc,max_bitrate,min_bitrate,start_bitrate);

	bbr_feedback_adapter_init(&cc->feedback);
	return cc;
}

void seadp_cc_destroy(seadp_cc_t* cc)
{
	if (cc == NULL)
		return;

	if (cc->pacer != NULL){
		bbr_pacer_destroy(cc->pacer);
		cc->pacer = NULL;
	}

	bbr_feedback_adapter_destroy(&cc->feedback);

	if (cc->bbr != NULL){
		bbr_destroy(cc->bbr);
		cc->bbr = NULL;
	}

	rte_free(cc);
	log_close();
}

void seadp_cc_set_bitrates(seadp_cc_t* cc, uint32_t max_bitrate, uint32_t min_bitrate, uint32_t start_bitrate)
{
	cc->max_bitrate = max_bitrate;
	cc->min_bitrate = min_bitrate;

	cc->target_bitrate = start_bitrate;

	bbr_pacer_set_bitrate_limits(cc->pacer, min_bitrate);
	bbr_pacer_set_pacing_rate(cc->pacer, start_bitrate/1000);

}

size_t  seadp_cc_get_cwnd(seadp_cc_t* cc){
	uint32_t req_cwnd_interval;
	int64_t now_ts;
	size_t cwnd;
	uint64_t pacing_cwnd;

	now_ts=GET_SYS_MS();
	cwnd=cc->info.congestion_window-cc->info.data_in_flight;
	if(cc->last_req_cwnd_ts==-1){
		cc->last_req_cwnd_ts=now_ts;
		cwnd=cwnd<kMaxCwnd?cwnd:kMaxCwnd;
		return (cwnd>0)?cwnd:0;
	}
	req_cwnd_interval=now_ts-cc->last_req_cwnd_ts;
	pacing_cwnd=req_cwnd_interval*cc->target_bitrate;
	cc->last_req_cwnd_ts = now_ts;
	if(cwnd>0){
		if(pacing_cwnd<cwnd){
			pacing_cwnd=pacing_cwnd<kMaxCwnd?pacing_cwnd:kMaxCwnd;
			return (pacing_cwnd>0)?pacing_cwnd:0;
		}
		else{
			cwnd=cwnd<kMaxCwnd?cwnd:kMaxCwnd;
			return (cwnd>0)?cwnd:0;
		}
	}
	else{
		return 0;
		}
}


void seadp_cc_heartbeat(seadp_cc_t* cc, int64_t now_ts)
{
	////sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	bbr_pacer_try_transmit((void*)cc,cc->pacer, now_ts);

	if (cc->bbr != NULL){
        //printf("cc->notify_ts:%lld, now_ts:%lld ,interval: %lld\n",cc->notify_ts,now_ts,now_ts-cc->notify_ts);
		cc->info = bbr_on_heartbeat(cc->bbr, now_ts);
		seadp_cc_on_network_invalidation(cc);
		//cc->notify_ts = now_ts;
	}
}

int seadp_cc_add_packet(seadp_cc_t* cc, cc_req_packet_t* req_packet)
{
	static int64_t last_ts = -1;
	uint32_t req_packet_add_interval;
	int64_t now_ts= GET_SYS_MS();
	if(last_ts == -1)
	{
		last_ts = now_ts;
	}
	req_packet_add_interval = now_ts - last_ts;
	last_ts = now_ts;
	return bbr_pacer_insert_packet(cc->pacer,req_packet,now_ts);
}

void seadp_cc_on_feedback(seadp_cc_t* cc, data_packet_t* data_packet)
{
	uint32_t acked_bitrate;
	if(!data_packet)
        return;

	if (data_packet->size <= 0)
		return;
    //将反馈信息传入feedback模块，计算ack速率，计算RTT，计算带宽？
	bbr_feedback_on_feedback(&cc->feedback,data_packet);
	if (cc->feedback.feedback.packet_number <= 0)
		return;

	if (cc->bbr != NULL){
		acked_bitrate = bbr_feedback_get_birate(&cc->feedback) / 8000;
		cc->info = bbr_on_feedback(cc->bbr, &cc->feedback.feedback, acked_bitrate);
		seadp_cc_on_network_invalidation(cc);
	}
}


static void seadp_cc_on_network_invalidation(seadp_cc_t* cc)
{
	size_t outstanding;
	double fill;

	uint32_t pacing_rate_kbps, target_rate_bps, instant_rate_kbps;
	int acked_bitrate;
	if (cc->info.congestion_window <= 0)
		return;

	/*设置pace参数*/
	pacing_rate_kbps = cc->info.pacer_config.data_window/cc->info.pacer_config.time_window;
	////sim_debug("pacing_rate_kBps:%d\n",pacing_rate_kbps);

	/*计算反馈带宽*/
	outstanding = bbr_feedback_get_in_flight(&cc->feedback);

	cc->info.data_in_flight=outstanding;
	////sim_debug("data_in_flight:%d\n",cc->info.data_in_flight);

	bbr_pacer_update_outstanding(cc->pacer, outstanding);

	instant_rate_kbps = cc->info.congestion_window / cc->info.target_rate.rtt;
	target_rate_bps = (SU_MIN(cc->info.target_rate.target_rate, instant_rate_kbps) * 8000);
	acked_bitrate = bbr_feedback_get_birate(&cc->feedback);
	cc->cc_acked_bitrate=acked_bitrate;
	//sim_debug("instant_rate_kbps :%dkBps,target_rate_bps:%dbps,acked_bitrate:%dbps\n",instant_rate_kbps,target_rate_bps ,acked_bitrate);

	fill = 1.0 * outstanding / cc->info.congestion_window;
	/*如果拥塞窗口满了，进行带宽递减*/
	if (fill > 1.0){
		cc->encoding_rate_ratio = 0.8f;
		if (acked_bitrate > 0){
			cc->target_bitrate = acked_bitrate * cc->encoding_rate_ratio;
		}
		else
			cc->target_bitrate = cc->target_bitrate * cc->encoding_rate_ratio;
	}
	else {
		cc->encoding_rate_ratio = 1;

		if (fill < 0.5){
			cc->target_bitrate = cc->target_bitrate + 64 * 1000;
		}
		else if (fill < 0.7){
			cc->target_bitrate = cc->target_bitrate + 32 * 1000;
		}
		else if (fill < 0.9){
			cc->target_bitrate = cc->target_bitrate + 16 * 1000;
		}
	}

	bbr_pacer_set_pacing_rate(cc->pacer, pacing_rate_kbps * 8);

	cc->target_bitrate = SU_MIN(target_rate_bps, cc->target_bitrate);
	cc->target_bitrate = SU_MAX(cc->target_bitrate, cc->min_bitrate);
	cc->target_bitrate = SU_MIN(cc->max_bitrate, cc->target_bitrate);
	//sim_debug(" func: %s, line:%d,cc->target_bitrate:%dbps\n",__FUNCTION__,__LINE__,cc->target_bitrate);
    ////sim_debug("cwnd : %d, data_in_flight:%d ,result:%d\n",cc->info.congestion_window,cc->info.data_in_flight,cc->info.congestion_window-cc->info.data_in_flight);
}

void   seadp_cc_remove_req_packet(seadp_cc_t* cc,uint32_t packet_number){
	return bbr_feedback_delete_send_history(&cc->feedback,packet_number);
}

static void seadp_cc_send_packet(seadp_cc_t* cc, uint16_t packet_no, size_t size)
{
	bbr_feedback_add_packet(&cc->feedback, packet_no, size);
}

uint32_t cc_get_bw(seadp_cc_t* cc)
{
	if(cc->cc_acked_bitrate==-1){
		return kDefaultACKBITRATE;
	}
	return cc->cc_acked_bitrate/8;
}
