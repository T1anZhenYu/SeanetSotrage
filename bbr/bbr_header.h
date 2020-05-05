
#ifndef __bbr_cc_header_h_
#define __bbr_cc_header_h_

#define MAX_REQ_SIZE 124

#include <stdint.h>
#include <stddef.h>

typedef struct
{
	uint16_t packet_no;
	size_t offset[MAX_REQ_SIZE];
	size_t size[MAX_REQ_SIZE];
	size_t count;
	size_t totalsize;
	int64_t send_ts;
	int    rtt;
}cc_req_packet_t;

typedef struct
{
	uint16_t packet_no;
	size_t offset;
	size_t size;
	int64_t send_ts;
	int64_t recv_ts;
}data_packet_t;

#endif
