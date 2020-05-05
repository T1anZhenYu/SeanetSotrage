#ifndef __SEADP_H__
#define __SEADP_H__
#include <stdint.h>
#include <rte_common.h>
//
//#define IPPROTO_EID 0x99U
//#define EID_ADDR_LEN 20
//
//struct eid_hdr {
//  uint8_t next_proto_id;
//  uint8_t hdr_len;
//  uint16_t flags;
//  uint8_t src_eid[EID_ADDR_LEN];
//  uint8_t dst_eid[EID_ADDR_LEN];
//} __rte_packed;
//
//#define EID_FLAG_NONE 0x0U
//
//#define EIDPROTO_SEADP 0x01U
//
//struct seadp_hdr {
//  uint16_t src_port;
//  uint16_t dst_port;
//#if __BYTE_ORDER == __BIG_ENDIAN
//  uint8_t version : 4, type : 4;
//#elif __BYTE_ORDER == __LITTLE_ENDIAN
//  uint8_t type : 4, version : 4;
//#endif
//  uint8_t hdr_len;
//  uint8_t cache_flag;
//  uint8_t storage_flag;
//  uint16_t seq;
//  uint16_t cksum;
//  uint32_t fragment_offset;
//  uint32_t total_len;
//} __rte_packed;
//
//#define SEADP_TYPE_REQ 0x8U
//#define SEADP_TYPE_DAT 0x4U
//#define SEADP_TYPE_SDAT 0x2U
//
//#define SEADP_CACHE_EN 0x80U
//
#endif  // !__SEADP_H__
