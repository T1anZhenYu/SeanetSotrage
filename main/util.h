#ifndef _UTIL_H_
#define _UTIL_H_

/**
 * @file
 *
 * Utility functions
 */

#include <rte_ip.h>
#include <stdint.h>

#include "Defaults.h"
#include "cs_two.h"

#define PACKET_PAYLOAD_LEN 1250
#define BITMAP_SHIFT 3  //移动3个位,左移则相当于乘以8,右移相当于除以8取整
#define BITMAP_MASK 0x07  // 16进制下的7

// ascii string convert to 16 Hexadecimal string
void char_array_2_hex_string(char* dest, unsigned char* source, int sourceLen);

void hex_string_2_char_array(char* dst, char* src, int srcLen);

/*将大写字母转换成小写字母*/
int Tolower(int c);

uint64_t htoi(char s[]);
/**
 * Return number of ports available in system among those specified by the
 * portmask.
 *
 * A port is available if physically connected and attached to DPDK drivers
 *
 * @param portmask
 *   The portmask of ports to be used by the DPDK application
 *
 * @return
 *   The ports available among those specified in the portmask
 */
uint8_t get_nb_ports_available(uint32_t portmask);
/**
 * Get number of lcores available to the DPDK application
 */
uint8_t get_nb_lcores_available(void);

/*
 * 置位函数——用"|"操作符,i&BITMAP_MASK相当于mod操作
 * m mod n 运算，当n = 2的X次幂的时候,m mod n = m&(n-1)
 */
// int set_bitmap_from_offset(int set_num, uint32_t offset, struct Bitmap_info
// *bitmap_info);

/* 查询位操作用&操作符 */
// int check_bitmap_from_offset(uint32_t offset, struct Bitmap_info
// *bitmap_info);

// void free_bitmap(struct Bitmap_info *bitmap_info);

// int bitmap_is_full(struct Bitmap_info *bitmap_info);

/*set all bit to 0*/
// int reset_bitmap(struct Bitmap_info *bitmap_info);

uint16_t cal_packet_num_of_chunk(uint32_t chunk_total_len);

#endif /* _UTIL_H_ */
