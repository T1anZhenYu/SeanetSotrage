#include "bbr_pacer.h"
#include <rte_malloc.h>
#define k_min_packet_limit_ms		5			/*������С���*/
#define k_max_packet_limit_ms		200			/*ÿ400������뷢��һ�����ģ���ֹ����ʧ��*/
#define k_max_interval_ms			30			/*�������ʱ����ʱ�䲻���ͱ���һ�η��ͺܶ����ݳ�ȥ�������籩*/
#define k_default_pace_factor		1.5			/*Ĭ�ϵ�pace factor����*/	


bbr_pacer_t* bbr_pacer_create(pace_send_func send_cb,uint32_t que_ms)
{
	bbr_pacer_t* pace = (bbr_pacer_t*)calloc(1, sizeof(bbr_pacer_t));
	pace->last_update_ts = GET_SYS_MS();
	pace->factor = k_default_pace_factor;
	pace->congestion_window_size = 0xffffffff;
	pace->send_cb = send_cb;
	pace->outstanding_bytes=0;
	pacer_queue_init(&pace->que,que_ms);
	init_interval_budget(&pace->media_budget, 0, -1);
	increase_budget(&pace->media_budget, k_min_packet_limit_ms);

	return pace;
}

void bbr_pacer_destroy(bbr_pacer_t* pace)
{
	if (pace == NULL)
		return;

	pacer_queue_destroy(&pace->que);

	rte_free(pace);
}

size_t bbr_get_req_packet_total_size(cc_req_packet_t* req_packet)
{
    int i;
    size_t totalsize = 0;
    
    if(req_packet == NULL)
        return 0;

    for(i=0; i < req_packet->count; i++)
    {
        totalsize += req_packet->size[i];
    }
    return totalsize;
}


int bbr_pacer_insert_packet(bbr_pacer_t* pace,cc_req_packet_t* req_packet,int64_t now_ts){
	packet_event_t ev;
	ev.packet_no = req_packet->packet_no;
	ev.size = req_packet->totalsize;
	ev.que_ts = now_ts;
	ev.sent = 0;
	
	return pacer_queue_push(&pace->que, &ev);
}

static int bbr_pacer_send(void* cc,bbr_pacer_t* pace, packet_event_t* ev)
{
	sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*���з��Ϳ���*/
	if (budget_remaining(&pace->media_budget) == 0)
		return -1;

	sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*�����ⲿ�ӿڽ������ݷ���*/
	int res=pace->send_cb(cc,ev->packet_no,ev->size);
	if(res!=0){
		printf("%d������ʧ��\n", ev->packet_no);
		return -1;
	}
	use_budget(&pace->media_budget, ev->size);
	pace->outstanding_bytes += ev->size;

	return 0;
}

void bbr_pacer_try_transmit(void* cc,bbr_pacer_t* pace, int64_t now_ts){
	int elapsed_ms;
	uint32_t target_bitrate_kbps;
	packet_event_t* ev;
	//ʱ����
	elapsed_ms = (int)(GET_SYS_MS() - pace->last_update_ts);
	sim_debug(" func: %s, line:%d,time:%d\n",__FUNCTION__,__LINE__,elapsed_ms);

	/*if (elapsed_ms < k_min_packet_limit_ms)
		return;*/
	elapsed_ms = SU_MIN(elapsed_ms, k_max_interval_ms);
	pace->last_update_ts = now_ts;
	/*����media budget����Ҫ������,�����µ�media budget֮��*/
	//����һ������ʹ�ö��п�����500ms�ڷ������
	if (pacer_queue_bytes(&pace->que) > 0){
            target_bitrate_kbps = pacer_queue_target_bitrate_kbps(&pace->que, now_ts);
            sim_debug(" func: %s, line:%d,target_bitrate_kbps:%d\n",__FUNCTION__,__LINE__,target_bitrate_kbps);
            target_bitrate_kbps = SU_MAX(pace->pacing_bitrate_kpbs, target_bitrate_kbps);            
	}
	else
		target_bitrate_kbps = pace->pacing_bitrate_kpbs;
	/*���¼�����Է��͵�ֱ������*/
	sim_debug(" func: %s, line:%d,pacing_bitrate_kpbs:%d,target_bitrate_kbps:%d\n",__FUNCTION__,__LINE__,pace->pacing_bitrate_kpbs,target_bitrate_kbps);
	set_target_rate_kbps(&pace->media_budget, target_bitrate_kbps);
	increase_budget(&pace->media_budget, elapsed_ms);
	sim_debug(" func: %s, line:%d\n",__FUNCTION__,__LINE__);
	/*���з���*/
	while (pacer_queue_empty(&pace->que) != 0){
		ev = pacer_queue_front(&pace->que);		
		if (bbr_pacer_send(cc,pace, ev) == 0)
			pacer_queue_sent(&pace->que, ev);
		else
			break;
		
	}
}

void bbr_pacer_set_bitrate_limits(bbr_pacer_t* pace, uint32_t min_bitrate)
{
	pace->min_sender_bitrate_kpbs = min_bitrate / 1000;
}

void bbr_pacer_set_pacing_rate(bbr_pacer_t* pace, uint32_t pacing_bitrate_kbps)
{
	pace->pacing_bitrate_kpbs = pacing_bitrate_kbps* pace->factor;
	pace->pacing_bitrate_kpbs = SU_MAX(pace->pacing_bitrate_kpbs, pace->min_sender_bitrate_kpbs) ;
} 

void bbr_pacer_update_outstanding(bbr_pacer_t* pace, size_t outstanding_bytes)
{
	pace->outstanding_bytes = outstanding_bytes;
}
