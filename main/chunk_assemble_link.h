#ifndef _CHUNK_ASSEMBLE_LINK_H
#define _CHUNK_ASSEMBLE_LINK_H

#include "cs_two.h"

#define PACKET_COPY_TO_DRAM_QUE 1
#define CHUNK_ASSEMBLE_SUCCESS 2
#define PACKET_ALREADY_EXIST 3

// 返回“双向链表的大小”
int dlink_size(int node_count);

// 新建“双向链表”。成功，0；否则，返回-1
int create_dlink(cs_two_t *cs, uint16_t dram_index);

// 新建“节点”。成功，返回节点指针；否则，返回NULL。
node *create_node(unsigned int pval1, unsigned int pval2);

// 获取“双向链表中第index位置的节点”
node *get_node(int index, int node_count, node *phead);

// 将“value”插入到index位置。成功，返回0；否则，返回-1。
int dlink_insert(
    int index, unsigned int pval1, unsigned int pval2, cs_two_t *cs,
    uint16_t
        dram_index);  // 将“value”插入到index位置。成功，返回0；否则，返回-1。

// 将“value”插入到表头位置。成功，返回0；否则，返回-1。
int dlink_insert_first(unsigned int pval1, unsigned int pval2, cs_two_t *cs,
                       uint16_t dram_index);

int dlink_start_change(int index, unsigned int pval1, int node_count,
                       node *phead);

int dlink_end_change(int index, unsigned int pval2, int node_count,
                     node *phead);

int dlink_delete(int index, cs_two_t *cs, uint16_t dram_index, node *phead);

// 撤销“双向链表”。成功，返回0；否则，返回-1
int destroy_dlink(cs_two_t *cs, uint16_t dram_index);  //被替换的时候销毁

int update_chunk_assemble_dlink_info_by_copy(cs_two_t *cs, uint32_t offset,
                                             uint16_t dram_index, char *payload,
                                             uint32_t payload_length,
                                             int node_count);

#endif