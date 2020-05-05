
#ifndef __sender_history_h_
#define __sender_history_h_

#include "estimator_common.h"
#include "bbr_common.h"
#include "common/cf_platform.h"
#include "cf_skiplist.h"
#include "cf_unwrapper.h"
#include "bbr_header.h"

typedef struct
{
	uint32_t		limited_ms;

	cf_unwrapper_t	wrapper;
	//int64_t			last_ack_pkt_num;
	skiplist_t*		l;
	size_t			outstanding_bytes;
}sender_history_t;

sender_history_t*	sender_history_create(uint32_t limited_ms);
void				sender_history_destroy(sender_history_t* hist);

void				sender_history_add(sender_history_t* hist, cc_req_packet_t* packet);
int					sender_history_get(sender_history_t* hist, data_packet_t* packet);

size_t				sender_history_outstanding_bytes(sender_history_t* hist);
void 				sender_history_remove(sender_history_t* hist,uint32_t packet_number);
#endif
