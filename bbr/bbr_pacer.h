
#ifndef __bbr_pacer_h_
#define __bbr_pacer_h_

#include "pacer_queue.h"
#include "interval_budget.h"
#include "bbr_header.h"

/*调用这个函数会通过seq在发送队列中找到对应的packet，并进行packet发送*/
typedef int(*pace_send_func)(void* handler, uint16_t packet_id, size_t size);

typedef struct
{
	uint32_t			min_sender_bitrate_kpbs;
	uint32_t			estimated_bitrate;
	uint32_t			pacing_bitrate_kpbs;

	int64_t				last_update_ts;

	pacer_queue_t		que;						/*排队队列*/
	interval_budget_t	media_budget;				/*正式的媒体报文的发送速度控制器*/
	interval_budget_t	padding_budget;				/*填充的发送速度控制器*/

	size_t				congestion_window_size;		/*拥塞窗口大小*/
	size_t				outstanding_bytes;			/*正在路上发送的数据*/
	float				factor;						/*pacing rate放大因子*/
	/*发包回调函数*/
	pace_send_func		send_cb;
}bbr_pacer_t;

bbr_pacer_t*				bbr_pacer_create(pace_send_func send_cb,uint32_t max_que_ms);
void						bbr_pacer_destroy(bbr_pacer_t* pace);

int 						bbr_pacer_insert_packet(bbr_pacer_t* pace,cc_req_packet_t* req_packet,int64_t now_ts);
void 						bbr_pacer_try_transmit(void* cc,bbr_pacer_t* pace, int64_t now_ts);
void 						bbr_pacer_set_bitrate_limits(bbr_pacer_t* pace, uint32_t min_bitrate);
void 						bbr_pacer_set_pacing_rate(bbr_pacer_t* pace, uint32_t pacing_bitrate_kbps);
void 						bbr_pacer_update_outstanding(bbr_pacer_t* pace, size_t outstanding_bytes);

#endif
