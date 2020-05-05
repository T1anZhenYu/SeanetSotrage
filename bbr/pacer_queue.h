/*-
* Copyright (c) 2017-2018 wenba, Inc.
*	All rights reserved.
*
* See the file LICENSE for redistribution information.
*/
#ifndef __pacer_queue_h_
#define __pacer_queue_h_

#include "common/cf_platform.h"
#include "cf_skiplist.h"
#include "cf_list.h"

#define k_max_pace_queue_ms			250			/*pacer queue���������ӳ�*/

typedef struct
{
	uint32_t		packet_no;			/*ͨ���е���������(��������)���൱��֡���Ⱥ�˳�*/
	size_t		size;/*����������ܴ�С*/
	int64_t		que_ts;			/*����pacer queue��ʱ���*/
	int		       sent;			/*�Ƿ��Ѿ�����*/
}packet_event_t;

typedef struct
{
	uint32_t		max_que_ms;		/*pacer���Խ��������ӳ�*/
	size_t			size;
	int64_t			oldest_ts;		/*����֡��ʱ���*/
	skiplist_t*		cache;			/*������SEQ�ŶӵĶ���*/
	base_list_t*	l;				/*��ʱ���Ⱥ�Ķ���*/
}pacer_queue_t;

void					pacer_queue_init(pacer_queue_t* que, uint32_t que_ms);
void					pacer_queue_destroy(pacer_queue_t* que);

int						pacer_queue_push(pacer_queue_t* que, packet_event_t* ev);
/*��ȡque����Сseq�İ�����˳�򷢳���������ֹ���ִ�Χ�Ķ���*/
packet_event_t*			pacer_queue_front(pacer_queue_t* que);
void					pacer_queue_sent_by_id(pacer_queue_t* que, uint32_t id);
void					pacer_queue_sent(pacer_queue_t* que, packet_event_t* ev);

int						pacer_queue_empty(pacer_queue_t* que);
size_t					pacer_queue_bytes(pacer_queue_t* que);
int64_t					pacer_queue_oldest(pacer_queue_t* que);
/*����que��Ҫ������*/
uint32_t				pacer_queue_target_bitrate_kbps(pacer_queue_t* que, int64_t now_ts);

#endif


