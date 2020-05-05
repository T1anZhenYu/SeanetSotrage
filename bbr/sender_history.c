
#include "sender_history.h"
#include <rte_malloc.h>

static void free_packet_feedback(skiplist_item_t key, skiplist_item_t val, void* args)
{
    cc_req_packet_t* packet = (cc_req_packet_t*)val.ptr;
    if (packet != NULL)
        rte_free(packet);
}


sender_history_t* sender_history_create(uint32_t limited_ms)
{
	sender_history_t* hist = (sender_history_t*)calloc(1, sizeof(sender_history_t));

	hist->limited_ms = limited_ms;
	hist->l = skiplist_create(id64_compare, free_packet_feedback, NULL);
	init_unwrapper16(&hist->wrapper);

	return hist;
}

void sender_history_destroy(sender_history_t* hist)
{
	if (hist == NULL)
		return;

	if (hist->l != NULL){
		skiplist_destroy(hist->l);
		hist->l = NULL;
	}

	frerte_free(hist);
}

void sender_history_add(sender_history_t* hist, cc_req_packet_t* packet)
{
    cc_req_packet_t* p;
    skiplist_iter_t* it;
    skiplist_item_t key, val;
    int segment_count;

    //sender_history_check_expired(hist); 此处是否添加待考虑

    key.i64 = wrap_uint16(&hist->wrapper, packet->packet_no);
    it = skiplist_search(hist->l, key);

    //该请求包未添加过
    if (it == NULL){

        p = (cc_req_packet_t*)rte_malloc(NULL,sizeof(cc_req_packet_t),0);
        *p = *packet;
        key.i64 = wrap_uint16(&hist->wrapper, packet->packet_no);
        val.ptr = p;
        skiplist_insert(hist->l, key, val);
        hist->outstanding_bytes += packet->totalsize;
    }
    else{ //不可能到达，因为pn是单调增加的
        printf("sender_history_add repeat!!!,pkt_no=%d\n",packet->packet_no);
    }
}


int sender_history_get(sender_history_t* hist, data_packet_t* packet)
{
    skiplist_iter_t* it;
    skiplist_item_t key;
    cc_req_packet_t* p;
    int seg_no,rtt;

    key.i64 = wrap_uint16(&hist->wrapper, packet->packet_no);
    it = skiplist_search(hist->l, key);
    if (it != NULL){
        p = (cc_req_packet_t*)it->val.ptr;
        p->totalsize-=packet->size;
        hist->outstanding_bytes = SU_MAX(hist->outstanding_bytes - packet->size, 0);
        if(p->rtt==0){
            p->rtt=packet->recv_ts-p->send_ts;
        }
        rtt=p->rtt;
        //sim_debug("xuxm: last_rtt = %d\n",p->rtt);
        if(p->totalsize<=0){
            //sim_debug("remove packet_no:%d\n",p->packet_no);
            skiplist_remove(hist->l, it->key);
        }
        return rtt>5?rtt:5;

    }
    return -1;
}

size_t sender_history_outstanding_bytes(sender_history_t* hist)
{
	return hist->outstanding_bytes;
}


void sender_history_remove(sender_history_t* hist,uint32_t packet_number)
{
    skiplist_iter_t* it;
    skiplist_item_t key;
    cc_req_packet_t* p;
    key.i64 = wrap_uint16(&hist->wrapper, packet_number);
    it = skiplist_search(hist->l, key);
    if(it != NULL){
        //当通知丢包的时候，需要删去网内相应的数据
        p = (cc_req_packet_t*)it->val.ptr;
        hist->outstanding_bytes = SU_MAX(hist->outstanding_bytes - p->totalsize, 0);
        //hist->outstanding_bytes = SU_MAX(hist->outstanding_bytes - packet->size, 0);
        skiplist_remove(hist->l, it->key);
        // printf("sender_history_remove %d ok\n",packet_number);
    }
    else
    {
        // printf("sender_history_remove %d  fail\n",packet_number);
    }
}
