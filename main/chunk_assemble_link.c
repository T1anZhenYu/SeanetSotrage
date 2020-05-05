#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <stdio.h>

#include "chunk_assemble_link.h"
#include "cs_two.h"

// 返回“双向链表的大小”
int dlink_size(int node_count) { return node_count; }

// 新建“双向链表”。成功，返回0；否则，返回-1。
int create_dlink(cs_two_t *cs, uint16_t dram_index) {
  // 创建表头
  cs->dram_queue[dram_index].phead = create_node(0, 0);
  if (!(cs->dram_queue[dram_index].phead)) {
    printf("create phead fail !\n");
    return -1;
  }
  // 设置“节点个数”为0
  cs->dram_queue[dram_index].node_count = 0;
  return 0;
}

// 新建“节点”。成功，返回节点指针；否则，返回NULL。
node *create_node(unsigned int pval1, unsigned int pval2) {
  node *pnode = NULL;
  pnode = (node *)rte_malloc(NULL, sizeof(node), RTE_CACHE_LINE_SIZE);
  if (!pnode) {
    printf("create node error!\n");
    return NULL;
  }
  // 默认的，pnode的前一节点和后一节点都指向它自身
  pnode->prev = pnode->next = pnode;

  // 节点的值为pval
  pnode->start = pval1;
  pnode->end = pval2;
  return pnode;
}

// 获取“双向链表中第index位置的节点”
node *get_node(int index, int node_count, node *phead) {
  int j = 0;
  node *rnode = phead->prev;

  if (index < 0 || index >= node_count) {
    printf("%s failed! index out of bound!\n", __func__);
    return NULL;
  }

  // printf("node_count is %d\n",node_count);
  // 正向查找
  if (index <= (node_count / 2)) {
    int i = 0;
    node *pnode = phead->next;
    while ((i++) < index) pnode = pnode->next;

    return pnode;
  }

  // 反向查找

  int rindex = node_count - index - 1;
  while ((j++) < rindex) rnode = rnode->prev;

  return rnode;
}

// 将“pval”插入到index位置。成功，返回0；否则，返回-1。
int dlink_insert(int index, unsigned int pval1, unsigned int pval2,
                 cs_two_t *cs, uint16_t dram_index) {
  // 插入表头
  if (index == 0) return dlink_insert_first(pval1, pval2, cs, dram_index);

  // 获取要插入的位置对应的节点
  node *pindex = get_node(index, cs->dram_queue[dram_index].node_count,
                          cs->dram_queue[dram_index].phead);
  if (!pindex) return -1;

  // 创建“节点”
  node *pnode = create_node(pval1, pval2);
  if (!pnode) return -1;

  pnode->prev = pindex->prev;
  pnode->next = pindex;
  pindex->prev->next = pnode;
  pindex->prev = pnode;
  // 节点个数+1
  cs->dram_queue[dram_index].node_count++;

  return 0;
}

// 将“pval”插入到表头位置
int dlink_insert_first(unsigned int pval1, unsigned int pval2, cs_two_t *cs,
                       uint16_t dram_index) {
  node *pnode = create_node(pval1, pval2);
  if (!pnode) return -1;

  pnode->prev = cs->dram_queue[dram_index].phead;
  pnode->next = cs->dram_queue[dram_index].phead->next;
  cs->dram_queue[dram_index].phead->next->prev = pnode;
  cs->dram_queue[dram_index].phead->next = pnode;
  cs->dram_queue[dram_index].node_count++;
  return 0;
}

//将第index位置的值start设置为pval1，成功返回0，否则返回1
int dlink_start_change(int index, unsigned int pval1, int node_count,
                       node *phead) {
  node *pindex = get_node(index, node_count, phead);
  if (pindex == NULL) return -1;

  pindex->start = pval1;
  return 0;
}

//将第index位置的值end设置为pval2，成功返回0，否则返回1
int dlink_end_change(int index, unsigned int pval2, int node_count,
                     node *phead) {
  node *pindex = get_node(index, node_count, phead);
  if (!pindex) return -1;

  pindex->end = pval2;
  return 0;
}

// 删除“双向链表中index位置的节点”。成功，返回0；否则，返回-1。
int dlink_delete(int index, cs_two_t *cs, uint16_t dram_index, node *phead) {
  node *pindex = get_node(index, cs->dram_queue[dram_index].node_count, phead);
  if (!pindex) {
    printf("%s failed! the index in out of bound!\n", __func__);
    return -1;
  }

  pindex->next->prev = pindex->prev;
  pindex->prev->next = pindex->next;
  rte_free(pindex);
  cs->dram_queue[dram_index].node_count--;

  return 0;
}

// 撤销“双向链表”。成功，返回0；否则，返回-1。
int destroy_dlink(cs_two_t *cs, uint16_t dram_index) {
  if (!cs->dram_queue[dram_index].phead) {
    printf("%s failed! dlink is null!\n", __func__);
    return -1;
  }

  node *pnode = cs->dram_queue[dram_index].phead->next;
  node *ptmp = NULL;
  while (pnode != cs->dram_queue[dram_index].phead) {
    ptmp = pnode;
    pnode = pnode->next;
    rte_free(ptmp);
  }

  rte_free(cs->dram_queue[dram_index].phead);
  cs->dram_queue[dram_index].phead = NULL;
  cs->dram_queue[dram_index].node_count = 0;

  return 0;
}

int update_chunk_assemble_dlink_info_by_copy(cs_two_t *cs, uint32_t offset,
                                             uint16_t dram_index, char *payload,
                                             uint32_t payload_len,
                                             int node_count) {
  uint8_t *addr_offset =
      cs->dram_queue[dram_index].dram_packet_pool_chunk_addr + offset;
  unsigned int temp = 0;
  int j = 0;
  node *pnode;
  node *phead = cs->dram_queue[dram_index].phead;

  // printf("0\n");
  for (j = 0; j < node_count; j++) {
    // printf("dlink_size()=%d\n", dlink_size());
    // printf("dlink_is_empty()=%d\n", dlink_is_empty());
    if (phead == NULL) {
      printf("the phead fail!\n");
    }
    pnode = get_node(j, node_count, phead);
    // printf("0\n");
    // printf("get_node(%d) start=%d\n", j, pnode->start);
    // printf("get_node(%d) end=%d\n", j, pnode->end);
    if (offset == pnode->start && offset + payload_len < pnode->end) {
      // printf("1\n");
      rte_memcpy(addr_offset, payload, payload_len);
      dlink_start_change(j, offset + payload_len, node_count, phead);
      // printf("1!\n");
      return PACKET_COPY_TO_DRAM_QUE;
    } else if (offset == pnode->start && offset + payload_len == pnode->end) {
      // printf("2\n");
      rte_memcpy(addr_offset, payload, payload_len);
      dlink_start_change(j, offset + payload_len, node_count, phead);

      if (dlink_size(cs->dram_queue[dram_index].node_count) == 1 &&
          pnode->start == pnode->end) {
        //printf("recv_finish\n");
        destroy_dlink(cs, dram_index);
        return CHUNK_ASSEMBLE_SUCCESS;
      } else {
        dlink_delete(j, cs, dram_index, phead);
      }
      return PACKET_COPY_TO_DRAM_QUE;
    } else if (offset > pnode->start && offset + payload_len < pnode->end) {
      // printf("3\n");
      rte_memcpy(addr_offset, payload, payload_len);
      temp = pnode->start;
      dlink_start_change(j, offset + payload_len, node_count, phead);
      dlink_insert(j, temp, offset, cs, dram_index);
      return PACKET_COPY_TO_DRAM_QUE;
    } else if (offset > pnode->start && pnode->end == offset + payload_len) {
      // printf("4\n");
      rte_memcpy(addr_offset, payload, payload_len);
      dlink_end_change(j, offset, node_count, phead);
      return PACKET_COPY_TO_DRAM_QUE;
    } else if (offset < pnode->start) {
      // printf("5\n");
      return PACKET_ALREADY_EXIST;
    }
  }
  return 0;
}