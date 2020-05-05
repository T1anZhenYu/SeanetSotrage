#ifndef __bbr_rtt_stats_h_
#define __bbr_rtt_stats_h_

#include "common/cf_platform.h"

#define MAX_INT64 (0x7fffffffffffffff)

typedef struct
{
	int64_t			latest_rtt;
	int64_t			min_rtt;
	int64_t			smoothed_rtt;
	int64_t			previous_srtt;

	int64_t			mean_deviation;
	int64_t			initial_rtt_us;
}bbr_rtt_stat_t;

void		bbr_rtt_init(bbr_rtt_stat_t* s);
void 		bbr_rtt_update(bbr_rtt_stat_t* s, int64_t send_delta, int64_t ack_delay);
int64_t		bbr_initial_rtt_us(bbr_rtt_stat_t* s);
int64_t		bbr_smoothed_rtt(bbr_rtt_stat_t* s);
int64_t 	bbr_min_rtt(bbr_rtt_stat_t* s);
int64_t		bbr_mean_deviation(bbr_rtt_stat_t* s);

#endif



