#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "Defaults.h"
#include "cs_two.h"
#include "util.h"

// ascii string convert to 16 Hexadecimal string
void char_array_2_hex_string(char* dest, unsigned char* source, int sourceLen) {
  int i;
  char highByte, lowByte;
  for (i = 0; i < sourceLen; i++) {
    highByte = source[i] >> 4;
    lowByte = source[i] & 0x0f;
    highByte += 0x30;
    if (highByte > 0x39) {
      dest[i * 2] = highByte + 0x07;
    } else {
      dest[i * 2] = highByte;
    }
    lowByte += 0x30;
    if (lowByte > 0x39) {
      dest[i * 2 + 1] = lowByte + 0x07;
    } else {
      dest[i * 2 + 1] = lowByte;
    }
  }
  return;
}

void hex_string_2_char_array(char* dst, char* src, int srcLen) {
  int i;
  char highByte, lowByte;
  for (i = 0; i < srcLen / 2; i++) {
    highByte = src[i * 2];
    lowByte = src[i * 2 + 1];
    highByte -= 0x30;
    if (highByte > 0x09) {
      highByte -= 0x07;
    }
    highByte = highByte << 4;

    lowByte -= 0x30;
    if (lowByte > 0x09) {
      lowByte -= 0x07;
    }

    dst[i] = highByte | lowByte;
  }
  return;
}

/*将大写字母转换成小写字母*/
int Tolower(int c) {
  if (c >= 'A' && c <= 'Z') {
    return c + 'a' - 'A';
  } else {
    return c;
  }
}

uint64_t htoi(char s[]) {
  int i;
  uint64_t n = 0;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    i = 2;
  } else {
    i = 0;
  }
  for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') ||
         (s[i] >= 'A' && s[i] <= 'Z');
       ++i) {
    if (Tolower(s[i]) > '9') {
      n = 16 * n + (10 + Tolower(s[i]) - 'a');
    } else {
      n = 16 * n + (Tolower(s[i]) - '0');
    }
  }
  return n;
}

uint8_t get_nb_ports_available(uint32_t portmask) {
  uint8_t port_id, nb_ports, nb_ports_available;
  nb_ports = rte_eth_dev_count();
  for (port_id = 0, nb_ports_available = 0; port_id < nb_ports; port_id++) {
    if ((portmask & (1 << port_id)) != 0) {
      nb_ports_available++;
    }
  }
  return nb_ports_available;
}

uint8_t get_nb_lcores_available(void) {
  uint8_t lcore_id, nb_lcores;
  for (lcore_id = 0, nb_lcores = 0; lcore_id < APP_MAX_LCORES; lcore_id++) {
    if (rte_lcore_is_enabled(lcore_id) == 1) {
      nb_lcores++;
    }
  }
  return nb_lcores;
}

/*
 * 置位函数——用"|"操作符,i&BITMAP_MASK相当于mod操作
 * m mod n 运算，当n = 2的X次幂的时候,m mod n = m&(n-1)
 */
/* int set_bitmap_from_offset(int set_num, uint32_t offset, struct Bitmap_info
*bitmap_info)
{
    uint32_t packet_num = offset / PACKET_PAYLOAD_LEN;
    if (bitmap_info == NULL){
        //printf("bitmap_info is not set!\n");
        return -1;
    }
    if (packet_num >= BITMAP_BYTE_LEN * 8){
        printf("BITMAP:sth wrong here, pkt num is %d\n", packet_num);
        return -1;
    }
    if(bitmap_info->bitmap == NULL){
        printf("BITMAP:bitmap is null!\n");
        return -1;
    }
    if (set_num == 1)
    {
        bitmap_info->bitmap[packet_num >> BITMAP_SHIFT] |= (1 << (packet_num &
BITMAP_MASK));
    }
    else if (set_num == 0)
    {
        bitmap_info->bitmap[packet_num >> BITMAP_SHIFT] &= ~(1 << (packet_num &
BITMAP_MASK));
    }
    else
    {
        return -1;
    }
    return 0;
}*/

/* 查询位操作用&操作符 */
/* int check_bitmap_from_offset(uint32_t offset, struct Bitmap_info
*bitmap_info)
{
    if (bitmap_info == NULL)
        return -1;
    int packet_num = offset / PACKET_PAYLOAD_LEN;
    if (packet_num < 0 || packet_num >=  BITMAP_BYTE_LEN * 8 ||
bitmap_info->bitmap == NULL) return -1; return (bitmap_info->bitmap[packet_num
>> BITMAP_SHIFT] & (1 << (packet_num & BITMAP_MASK))) >> (packet_num &
BITMAP_MASK);
}


void free_bitmap(struct Bitmap_info *bitmap_info)
{
    if (bitmap_info == NULL)
        return;
    if (bitmap_info->bitmap != NULL)
        free(bitmap_info->bitmap);
    free(bitmap_info);
}

int bitmap_is_full(struct Bitmap_info *bitmap_info)
{
    int i;
    uint16_t quotient, remain;
    uint8_t a = 255; //255 means that every bit is 1 in uint8_t type
    if (bitmap_info == NULL)
        return -1;
    if (bitmap_info->bitmap == NULL || bitmap_info-> packet_num_of_one_chunk==
0) return -1; quotient = bitmap_info->packet_num_of_one_chunk / BITMAP_WORD;
    remain = bitmap_info->packet_num_of_one_chunk % BITMAP_WORD;
    //printf("%d %d %d  %d\n", BITMAP_WORD,
bitmap_info->packet_num_of_one_chunk, quotient, remain); for (i = 0; i <
quotient; i++)
    {
        //consider which operation is faster
        if (bitmap_info->bitmap[i] != a)
            return 0;
    }
    for (i = 0; i < remain; i++)
    {
        if (check_bitmap_from_offset(bitmap_info->packet_num_of_one_chunk - 1 -
i, bitmap_info) == 0) return 0;
    }
    return 1;
}*/

/*set all bit to 0*/
/* int reset_bitmap(struct Bitmap_info *bitmap_info)
{
    int i;
    if (bitmap_info == NULL)
        return -1;
    if (bitmap_info->bitmap == NULL)
        return -1;
    bitmap_info->packet_num_of_one_chunk = 0;
    for (i = 0; i < BITMAP_BYTE_LEN; i++)
    {
        bitmap_info->bitmap[i] = 0;
    }
    return 0;
}*/

uint16_t cal_packet_num_of_chunk(uint32_t chunk_total_len) {
  uint16_t result, remain = 0;
  remain = chunk_total_len % PACKET_PAYLOAD_LEN;
  result = chunk_total_len / PACKET_PAYLOAD_LEN;
  if (remain > 0) {
    result++;
  }
  return result;
}
