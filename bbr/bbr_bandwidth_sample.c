#include "bbr_bandwidth_sample.h"
#include <rte_malloc.h>

#define kMaxTrackedPackets  10000
#define kDefaultPoints		1024

//////////////////////////////////////////////////////////////////////////////////////////////////////////
static void sampler_add_point(bbr_bandwidth_sampler_t* sampler, int64_t sent_time, int64_t number, size_t data_size)
{

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
bbr_bandwidth_sampler_t* sampler_create()
{
	bbr_bandwidth_sampler_t* sampler = (bbr_bandwidth_sampler_t*)calloc(1, sizeof(bbr_bandwidth_sampler_t));

	sampler->size = kDefaultPoints;
	sampler->points = (bbr_packet_point_t*) rte_malloc(NULL,sampler->size * sizeof(bbr_packet_point_t),0);

	sampler_reset(sampler);

	return sampler;
}

void sampler_destroy(bbr_bandwidth_sampler_t* sampler)
{
	if (sampler != NULL){
		rte_free(sampler->points);
		rte_free(sampler);
	}
}

void sampler_reset(bbr_bandwidth_sampler_t* sampler)
{
	int i;
	bbr_packet_point_t* point;

	sampler->total_data_sent = 0;
	sampler->total_data_acked = 0;
	sampler->total_data_sent_at_last_acked_packet = 0;
	sampler->last_acked_packet_sent_time = -1;
	sampler->last_acked_packet_ack_time = -1;
	sampler->last_sent_packet = 0;
	sampler->rate_bps = -1;

	sampler->is_app_limited = 0;
	sampler->end_of_app_limited_phase = 0;

	sampler->start_pos = -1;
	sampler->index = -1;
	sampler->count = 0;
	for (i = 0; i < sampler->size; ++i){
		point = &sampler->points[i];

		point->send_time = 0;
		point->size = 0;

		point->total_data_sent = 0;
		point->total_data_acked_at_the_last_acked_packet = 0;
		point->total_data_sent_at_last_acked_packet = 0;

		point->last_acked_packet_ack_time = -1;
		point->last_acked_packet_sent_time = -1;
		point->is_app_limited = 0;
		point->ignore = 1;
	}
}

void	sampler_on_packet_sent(bbr_bandwidth_sampler_t* sampler, int64_t sent_time, int64_t packet_number, size_t data_size, size_t data_in_flight)
{
	sampler->last_sent_packet = packet_number;
	sampler->total_data_sent += data_size;

	if (data_in_flight <= 0){
		sampler->last_acked_packet_ack_time = sent_time;
		sampler->last_acked_packet_sent_time = sent_time;

		sampler->total_data_sent_at_last_acked_packet = sampler->total_data_sent;
	}

	if (sampler->index >= 0 && sampler->index + kMaxTrackedPackets < packet_number)
		return;

	sampler_add_point(sampler, sent_time, packet_number, data_size);
}

