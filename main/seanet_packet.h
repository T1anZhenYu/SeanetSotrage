#ifndef _SEANET_PACKET_PRASE_H_
#define _SEANET_PACKET_PRASE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>





struct seanet_hdr{
    uint8_t id_next_head_type ;
    uint8_t id_length ;
    uint16_t id_seanet_prot_prop;
    char id_src_eid[20] ;                  
    char id_dst_eid[20] ;
} __attribute__((__packed__));

struct seadp_hdr{ 
    uint16_t seadp_src_port ;
    uint16_t seadp_dst_port ;
    uint8_t version_n_type;
    uint8_t hdr_len;
    uint8_t seadp_cache_type;
    uint8_t storage_flag;
    uint16_t seadp_packet_order;
    uint16_t seadp_checksum ;
    //uint16_t seadp_tran_type_res ;//unsigned short tflag:4,reserve:12;
    uint32_t seadp_packet_offset ;
    uint32_t seadp_chunk_total_len ;
} __attribute__((__packed__));

struct register_hdr
{
uint32_t isGlobalVisable;
uint32_t delayParameter;
unsigned char connect_2_gnr_type;
unsigned char ttl;
char eid[20] ;
} __attribute__((__packed__));




#endif /* _SEANET_PACKET_PRASE_H_ */
