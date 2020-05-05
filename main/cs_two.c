/*
Author : zengl
build a hash table to manage the hierarchical content store
on dram and cs
*/

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "chunk_assemble_link.h"
#include "cs_two.h"
#include "dpdk_rcv.h"
#include "util.h"

#define CS_TWO_LOG(...) RTE_LOG(DEBUG, USER1, "[CS_TWO_LOG]: " __VA_ARGS__)

#define CS_TWO_WARN(...) RTE_LOG(WARNING, USER1, "[CS_TWO_WARN]: " __VA_ARGS__)

static uint8_t dram_queue_is_full(cs_two_t *cs)
{
   return cs->dram_queue_size == cs->dram_queue_max_element;
}

static uint8_t dram_queue_is_empty(cs_two_t *cs)
{
  return cs->dram_queue_size == 0;
}

uint32_t get_bucket_from_hex_eid(uint32_t bucket_num_for_cs_two, char *eid)
{
  uint64_t short_eid;
  uint32_t bucket;
  char eid_short_array[17];
  memcpy(eid_short_array, eid, 16);
  eid_short_array[16] = '\0';
  short_eid = htoi(eid_short_array);
  // printf("the short eid is %lu!\n",short_eid);
  bucket = (uint32_t)(short_eid % (uint64_t)bucket_num_for_cs_two);
  return bucket;
}

uint32_t dram_queue_get_insert_index(cs_two_t *cs)
{
  uint32_t insertPosIndex = 0;
  uint32_t head, tail;

  head = cs->dram_queue_head_index;
  tail = cs->dram_queue_tail_index;

  if (dram_queue_is_empty(cs))
  {
    cs->dram_queue[head].prev_index = tail;
    cs->dram_queue[tail].next_index = head;
    insertPosIndex = head;
  }
  else
  {
    /* first check whether the dram queue is full, if it is full, we need to
     * evict an element */
    if (dram_queue_is_full(cs))
    {
      uint32_t to_be_tail = cs->dram_queue[tail].prev_index;
      uint32_t to_be_head = tail;

      cs->dram_queue[to_be_head].prev_index = to_be_tail;
      cs->dram_queue[to_be_head].next_index = head;

      cs->dram_queue[head].prev_index = to_be_head;
      cs->dram_queue[to_be_tail].next_index = to_be_head;

      cs->dram_queue_head_index = to_be_head;
      cs->dram_queue_tail_index = to_be_tail;

      insertPosIndex = tail;

      return insertPosIndex;
    }
    else
    {
      cs->dram_queue[cs->dram_queue_size].next_index = head;
      cs->dram_queue[cs->dram_queue_size].prev_index = tail;

      cs->dram_queue[head].prev_index = cs->dram_queue_size;
      cs->dram_queue[tail].next_index = cs->dram_queue_size;

      cs->dram_queue_head_index = cs->dram_queue_size;

      insertPosIndex = cs->dram_queue_head_index;
    }
  }

  /* DRAM queue is not full, so we need to add the size */
  cs->dram_queue_size += 1;

  return insertPosIndex;
}

uint32_t dram_queue_update_by_visit_index(struct cs_two *cs, uint32_t index)
{
  uint32_t head = cs->dram_queue_head_index;
  uint32_t tail = cs->dram_queue_tail_index;

  if (index > cs->dram_queue_max_element - 1)
  {
    CS_TWO_LOG("This index %u exceeds the size of the dram queue \n", index);
    return 0;
  }

  /* we should move the visited item to the front */
  if (index == head)
  {
  }
  else if (index == tail)
  {
    uint32_t to_be_head = tail;
    uint32_t to_be_tail = cs->dram_queue[tail].prev_index;

    cs->dram_queue[to_be_head].prev_index = to_be_tail;
    cs->dram_queue[to_be_tail].next_index = to_be_head;

    cs->dram_queue_head_index = to_be_head;
    cs->dram_queue_tail_index = to_be_tail;
  }
  else
  {
    uint32_t to_be_head = index;

    cs->dram_queue[cs->dram_queue[index].prev_index].next_index =
        cs->dram_queue[index].next_index;

    cs->dram_queue[cs->dram_queue[index].next_index].prev_index =
        cs->dram_queue[index].prev_index;

    cs->dram_queue[head].prev_index = to_be_head;
    cs->dram_queue[tail].next_index = to_be_head;
    cs->dram_queue[to_be_head].next_index = head;
    cs->dram_queue[to_be_head].prev_index = tail;

    cs->dram_queue_head_index = to_be_head;
  }

  return 0;
}

static inline int copy_chunk_to_dram_lru_in_write(struct cs_two *cs,
                                                  uint16_t dram_index,
                                                  char *payload)
{
  rte_memcpy(cs->dram_queue[dram_index].dram_packet_pool_chunk_addr, payload,
             SIZE_OF_ONE_CHUNK);
  return 0;
}

static inline void push_chunk_to_other_core(
    struct rte_mempool *shm_message_pool, struct rte_ring *shm_ring_queue,
    cs_two_t *cs, uint16_t index, struct chunk_msg_desc *msg,
    unsigned lcore_id)
{
  if (rte_mempool_get(shm_message_pool, (void **)&msg) < 0)
  {
    CS_TWO_WARN(
        "Not enough entries in the mempool on message packet pool on socket:%u "
        "\n",
        rte_socket_id());
  }
  else
  {
    RTE_LOG(DEBUG, USER1, "[lcore %d]the dram index of this chunk is %d\n",
            lcore_id, index);
    // printf("the chunk addr is %p\n",
    // cs->dram_queue[index].dram_packet_pool_chunk_addr);
    if (msg == NULL)
    {
      // This usually can not happen
      CS_TWO_WARN("chunk desc is invalid when pushing a chunk to fisk core \n");
      return;
    }
    rte_memcpy(msg->chunk, cs->dram_queue[index].dram_packet_pool_chunk_addr,
               SIZE_OF_ONE_CHUNK);

    uint32_t bucket = cs->dram_queue[index].bucket;
    uint8_t tab = cs->dram_queue[index].tab;

    // Notice: the hash value should be the one that will be replaced, rather
    // the one that will be inserted.
    rte_memcpy(msg->chunk_eid,
               cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
               EID_LEN_HEX + 1);
               ol type 标识数据包（写如文件系统之前 lru放到dram  再读的时候先找dram看一下 加io为read再去fs再找    请求包  
               有限
    msg->io_type = REQUEST_IO_WRITE;
    if (rte_ring_enqueue(shm_ring_queue, msg) < 0)
    {
      CS_TWO_WARN("Not enough room in the ring to enqueue on socket:%u \n",
                  rte_socket_id());

      rte_mempool_put(shm_message_pool, msg);
      return;
    }
  }
}

/**
 * judge if a content represented by crc is in cache or not
 *
 * @cs
 *    data structure of h2c
 * @crc
       hash value of the content
 * @return
 *      0:   this content is in cache
 *     -1:   this content is not in cache
*/
static inline int lookup_cache(cs_two_t *cs, uint32_t bucket, char *eid)
{
  // uint32_t hash_bucket;
  uint8_t tab;
  uint8_t exit_flag = 0;
  // int8_t type;

  // hash_bucket = bucket;

  while (1)
  {
    if (exit_flag == 1)
    {
      break;
    }

    for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++)
    {
      if (likely(cs->hash_table[bucket].entry[tab].busy == 0))
      {
        return -1;
        // if (bucket == hash_bucket)
        //{
        //    continue;
        //}
        // else
        //{
        // In this case, we iterate a bucket, but this element is null, which
        // indicates that the element must not exist, otherwise this element
        // must be occupied in the inserting process
        // exit_flag = 1;
        // break;
        //}
      }

      if (strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                 eid) != 0)
      {
        CS_TWO_LOG(" hash[%u].entry[%u] don't have this eid chunk \n", bucket,
                   tab);
        continue;
      }

      if ((cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_FISK) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_WRITE_DRAM) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_BOTH) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_DRAM)) // chunk has stored in fisk，rather in dram
      {
        return 0;
      }

      if (cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_IS_WRITTING)
      {
        CS_TWO_LOG(
            "looking up...but the chunk is writting to writter core, we "
            "supposed to it would been store successful!\n");
        return 0;
      }

      if ((cs->hash_table[bucket].entry[tab].dram_flag == 0) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_JUST_IN_HASH)) // chunk or packet store in DRAM
      {
        if (cs->hash_table[bucket].entry[tab].assemble_flag ==
            COMPLETE) // chunk has assembled successfully
        {
          return 0;
        }
        else
        { // chunk has not assembled successfully
          // CS_TWO_LOG("chunk has not assembled successfully\n");
          return -1;
        }
        //}
      }
    }
    bucket = (bucket + 1) % cs->hash_table_num_buckets;
  }
  return -1;
}

//  70.8W, 1280
struct cs_two *cs_two_create(uint32_t hash_table_num_buckets,
                             uint32_t dram_queue_max_element, int socket)
{
  struct cs_two *cs;
  void *p;
  uint32_t i, j;

  /* Allocate space for cs structure */
  p = rte_zmalloc_socket("CS_TWO", sizeof(struct cs_two), RTE_CACHE_LINE_SIZE,
                         socket);
  if (p == NULL)
  {
    CS_TWO_WARN("the struct cs two malloc fail for assemble core!\n");
    return NULL;
  }

  cs = (struct cs_two *)p;

  cs->hash_table_num_buckets = hash_table_num_buckets;

  /* Allocate space for the actual hash-table */
  p = rte_malloc_socket(
      "CS_TWO_HASH_TABLE",
      cs->hash_table_num_buckets * sizeof(struct cs_two_htbl_bucket),
      RTE_CACHE_LINE_SIZE, socket);
  if (p == NULL)
  {
    CS_TWO_WARN("the hash table for assemble core malloc fail!\n");
    return NULL;
  }

  cs->hash_table = (struct cs_two_htbl_bucket *)p;
  cs->dram_queue_max_element = dram_queue_max_element;

  /* Allocate space for hash table per entry */
  for (i = 0; i < cs->hash_table_num_buckets; i++)
  {
    for (j = 0; j < ENTRY_NUM_OF_ONE_BUCKET; j++)
    {
      p = rte_malloc_socket("ENTRY_CHUNK_INFO",
                            sizeof(struct chunk_assemble_info),
                            RTE_CACHE_LINE_SIZE, socket);
      if (p == NULL)
      {
        CS_TWO_WARN("struct chunk_assemble_info malloc fail!\n");
        return NULL;
      }
      cs->hash_table[i].entry[j].chunk_info = (struct chunk_assemble_info *)p;
    }
  }

  /* Allocate space for dram queue */
  p = rte_malloc_socket(
      "CS_DRAM_QUEUE",
      cs->dram_queue_max_element * sizeof(struct cs_dram_queue),
      RTE_CACHE_LINE_SIZE, socket);

  if (p == NULL)
  {
    CS_TWO_WARN(
        "struct dram lru queue malloc for assemble core cs two fail!\n");
    return NULL;
  }

  cs->dram_queue = (struct cs_dram_queue *)p;
  cs->dram_queue_head_index = 0;
  cs->dram_queue_tail_index = 0;
  cs->dram_queue_size = 0;

  /* Allocate 2MB memory for each chunk in dram queue */
  // 1280
  for (i = 0; i < cs->dram_queue_max_element; i++)
  {
    p = rte_malloc_socket("QUE_PER_CHUNK_ADDR", SIZE_OF_ONE_CHUNK,
                          RTE_CACHE_LINE_SIZE, socket);
    if (p == NULL)
    {
      CS_TWO_WARN("dram lru queue malloc for assemble core cs two fail!\n");
      return NULL;
    }
    cs->dram_queue[i].dram_packet_pool_chunk_addr = (uint8_t *)p;
  }

  return cs;
}

//  70.8W, 1280
struct cs_two *cs_two_create_for_write(uint32_t dram_queue_max_element,
                                       int socket)
{
  struct cs_two *cs;
  void *p;
  uint32_t i, j;

  /* Allocate space for cs structure */
  p = rte_zmalloc_socket("CS_TWO", sizeof(struct cs_two), RTE_CACHE_LINE_SIZE,
                         socket);
  if (p == NULL)
  {
    CS_TWO_WARN("the struct cs two malloc fail for write core!\n");
    return NULL;
  }

  cs = (struct cs_two *)p;

  cs->hash_table_num_buckets = 0;

  /* Allocate space for the actual hash-table */
  p = rte_zmalloc_socket("CS_TWO_HASH_TABLE", sizeof(struct cs_two_htbl_bucket),
                         RTE_CACHE_LINE_SIZE, socket);
  if (p == NULL)
  {
    CS_TWO_WARN("the hash table for write malloc fail!\n");
    return NULL;
  }

  cs->hash_table = (struct cs_two_htbl_bucket *)p;
  cs->dram_queue_max_element = dram_queue_max_element;

  /* Allocate space for hash table per entry */

  for (j = 0; j < ENTRY_NUM_OF_ONE_BUCKET; j++)
  {
    p = rte_zmalloc_socket("ENTRY_CHUNK_INFO",
                           sizeof(struct chunk_assemble_info),
                           RTE_CACHE_LINE_SIZE, socket);
    if (p == NULL)
    {
      CS_TWO_WARN("struct chunk_assemble_info for write malloc fail!\n");
      return NULL;
    }
    cs->hash_table[0].entry[j].chunk_info = (struct chunk_assemble_info *)p;
  }

  /* Allocate space for dram queue */
  p = rte_malloc_socket(
      "CS_DRAM_QUEUE",
      cs->dram_queue_max_element * sizeof(struct cs_dram_queue),
      RTE_CACHE_LINE_SIZE, socket);
  if (p == NULL)
  {
    CS_TWO_WARN("struct dram lru queue malloc for write cs two fail!\n");
    return NULL;
  }

  cs->dram_queue = (struct cs_dram_queue *)p;
  cs->dram_queue_head_index = 0;
  cs->dram_queue_tail_index = 0;
  cs->dram_queue_size = 0;

  /* Allocate 2MB memory for each chunk in dram queue */
  // 1280
  for (i = 0; i < cs->dram_queue_max_element; i++)
  {
    p = rte_malloc_socket("QUE_PER_CHUNK_ADDR", SIZE_OF_ONE_CHUNK,
                          RTE_CACHE_LINE_SIZE, socket);
    if (p == NULL)
    {
      CS_TWO_WARN(
          "dram lru queue per element malloc for write cs two fail!the i is "
          "%d\n",
          i);
      return NULL;
    }
    cs->dram_queue[i].dram_packet_pool_chunk_addr = (uint8_t *)p;
    cs->dram_queue[i].node_count = 0;
  }

  return cs;
}

static inline int8_t __cs_two_insert_with_hash(
    struct rte_mempool *shm_message_pool, struct rte_ring *shm_ring_queue,
    uint32_t offset, uint32_t payload_len, cs_two_t *cs, char *payload,
    char *eid, uint32_t bucket_num_for_cs_two)
{
  struct chunk_msg_desc *msg = NULL; /**< used to send a message to SSD IO core
                                        when dram queue is full */

  uint32_t bucket;
  uint8_t tab;
  // uint32_t pool_index, j;
  // uint8_t  *packet;                     /**< point to real network packet */

  uint32_t dram_queue_insert_index = 0;
  uint32_t dram_queue_index_from_entry; /**< store the dram queue index from an
                                           existed hash table entry */

  uint32_t bucket_of_replaced_chunk,
      tab_of_replaced_chunk; /**< tmp variable to record chunk that will be
                                replaced */
  unsigned lcore_id;
  int node_count;
  int ret;

  lcore_id = rte_lcore_id();

  // uint64_t begin_rtc, end_rtc;
  // float    us_value;

  bucket =
      get_bucket_from_hex_eid(bucket_num_for_cs_two, eid); /**< Get index of corresponding bucket */
  // printf("the bucket calcuatd by eid is %d\n", bucket);
  if (lookup_cache(cs, bucket, eid) == 0)
  {
    // printf("this content has detected in hash table\n");
    return 0;
  }

  while (1)
  {
    // Iterate all buckets till find one free and insert
    for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++)
    {
      // first packet of this chunk
      if (likely(cs->hash_table[bucket].entry[tab].busy == 0))
      {
        RTE_LOG(DEBUG, USER1, "worker first eis %s! \n", eid);
        // If the dram queue is full, one of the segments will be replaced based
        // on LRU strategy.

        if (dram_queue_is_full(cs))
        {
          CS_TWO_LOG(
              "the dram queue is full! we need delete a index in dram "
              "queue,and insert new one!\n");
          RTE_LOG(DEBUG, USER1,
                  "the dram queue is full! we need delete a index in dram "
                  "queue,and insert new one!\n");
          dram_queue_insert_index = dram_queue_get_insert_index(cs);
          // CS_TWO_LOG("the dram queue insert index is
          // %d!\n",dram_queue_insert_index_tem);

          // the dram lru queue is full, if the last index has assemblede
          // succssfully, we delete it and pull new content into this index.
          // otherwise, we take content into a loop, we lookup the (index-n)'s
          // index, if (index-n)'s index.assemble_flag == COMPLETE we insert new
          // content into (index-n)'s index

          bucket_of_replaced_chunk =
              cs->dram_queue[dram_queue_insert_index].bucket;
          tab_of_replaced_chunk = cs->dram_queue[dram_queue_insert_index].tab;
          if (cs->hash_table[bucket_of_replaced_chunk]
                  .entry[tab_of_replaced_chunk]
                  .assemble_flag == COMPLETE)
          {
            if ((cs->hash_table[bucket_of_replaced_chunk]
                     .entry[tab_of_replaced_chunk]
                     .dram_flag == CHUNK_STORE_IN_BOTH) ||
                (cs->hash_table[bucket_of_replaced_chunk]
                     .entry[tab_of_replaced_chunk]
                     .dram_flag == CHUNK_STORE_IN_WRITE_DRAM) ||
                (cs->hash_table[bucket_of_replaced_chunk]
                     .entry[tab_of_replaced_chunk]
                     .dram_flag == CHUNK_STORE_IN_FISK))
            {
              CS_TWO_LOG(
                  "the dram_queue[%u] content had stored in write core,we "
                  "delete it in dram queue,"
                  "but it still store in fisk!the new chunk is %s \n",
                  dram_queue_insert_index, eid);
              // when chunk is stored in write core, the dram flag has fixed, so
              // we don't need to change it. in term of dram index, write core
              // has also modify it so that the dram index indicate the dram
              // index in the write core lru queue
              // cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag
              // = CHUNK_STORE_IN_FISK;
              // cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_index
              // = 0;
            }
            else if (cs->hash_table[bucket_of_replaced_chunk]
                         .entry[tab_of_replaced_chunk]
                         .dram_flag == CHUNK_STORE_IN_DRAM)
            {
              CS_TWO_LOG(
                  "unexcepted situation! dram flag indicate this chunk had "
                  "assembled in LRU successfully,but it hasn't write in file "
                  "system until now");

              cs->hash_table[bucket_of_replaced_chunk]
                  .entry[tab_of_replaced_chunk]
                  .dram_flag = CHUNK_IS_WRITTING;
              cs->hash_table[bucket_of_replaced_chunk]
                  .entry[tab_of_replaced_chunk]
                  .dram_index = 0;
            }
            else if (cs->hash_table[bucket_of_replaced_chunk]
                         .entry[tab_of_replaced_chunk]
                         .dram_flag == CHUNK_IS_WRITTING)
            {
              CS_TWO_LOG(
                  "chunk is writting!we delete it in worker core dram lru!\n");
              cs->hash_table[bucket_of_replaced_chunk]
                  .entry[tab_of_replaced_chunk]
                  .dram_index = 0;
            }
          }
          else if (cs->hash_table[bucket_of_replaced_chunk]
                       .entry[tab_of_replaced_chunk]
                       .assemble_flag == NOT_COMPLETE)
          {
            CS_TWO_LOG(
                "the dram_queue[%u] content didn't assembled,may drop had "
                "happened ,we delete it in dram queue,"
                "the new chunk is %s \n",
                dram_queue_insert_index, eid);
            cs->hash_table[bucket_of_replaced_chunk]
                .entry[tab_of_replaced_chunk]
                .dram_flag = CHUNK_JUST_IN_HASH;
            cs->hash_table[bucket_of_replaced_chunk]
                .entry[tab_of_replaced_chunk]
                .dram_index = 0;
          }

          create_dlink(cs, dram_queue_insert_index);
          dlink_insert(FIRST_NODE_INDEX, 0, SIZE_OF_ONE_CHUNK, cs,
                       dram_queue_insert_index);
          node_count =
              dlink_size(cs->dram_queue[dram_queue_insert_index].node_count);
        }
        else
        {
          dram_queue_insert_index = dram_queue_get_insert_index(cs);
          create_dlink(cs, dram_queue_insert_index);
          dlink_insert(FIRST_NODE_INDEX, 0, SIZE_OF_ONE_CHUNK, cs,
                       dram_queue_insert_index);
          node_count =
              dlink_size(cs->dram_queue[dram_queue_insert_index].node_count);
        }

        CS_TWO_LOG("the dram index of first packet is %d\n",
                   dram_queue_insert_index);
        CS_TWO_LOG("the node count is %d!\n", node_count);
        if (likely(update_chunk_assemble_dlink_info_by_copy(
                       cs, offset, dram_queue_insert_index, payload,
                       payload_len, node_count) == PACKET_COPY_TO_DRAM_QUE))
        {
          // Associate this chunk with this entry in hash table
          cs->hash_table[bucket].entry[tab].busy = 1;
          cs->hash_table[bucket].entry[tab].dram_flag = 0;
          cs->hash_table[bucket].entry[tab].assemble_flag = NOT_COMPLETE;
          cs->hash_table[bucket].entry[tab].dram_index =
              dram_queue_insert_index;

          cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len = 1;
          // tem_chunk_len means that the recent received packet num of chunk
          strcpy(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid, eid);

          // Associate this chunk with the dram queue. Packet pool index will be
          // associated afterwards.
          cs->dram_queue[dram_queue_insert_index].req_cnt = 1;
          cs->dram_queue[dram_queue_insert_index].bucket = bucket;
          cs->dram_queue[dram_queue_insert_index].tab = tab;

          // CS_TWO_LOG("First Packet of the chunk , the eid is %s!\n DRAM Index
          // %u \n", eid, dram_queue_insert_index);
        }
        else
        {
          // This code can not be reached if we set the packet buffer number of
          // packet pool carefully.
          CS_TWO_WARN(
              "Insert first chunk ing... but wrong situation happen! \n");
          rte_exit(EXIT_FAILURE,
                   "lcore_id:%u, Insert first chunk ing... but wrong situation "
                   "happen! \n",
                   rte_lcore_id());
          // return 0;
        }
        return 0;
      }
      else // This hash table entry is occupied, meaning that at least one
           // packet of the chunk has been received.
      {
        // CS_TWO_LOG("This hash table entry is occupied, meaning that at least
        // one  packet of the chunk has been received.\n"); CS_TWO_LOG("tem len:
        // %u\n", cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len);
        // The hash value of this chunk should be equal to the one recorded in
        // the dram segment queue.
        if (likely(
                strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                       eid) == 0))
        {
          if (unlikely(cs->hash_table[bucket].entry[tab].dram_flag ==
                       CHUNK_JUST_IN_HASH))
          {
            // If the dram queue is full, one of the segments will be replaced
            // based on LRU strategy.
            if (dram_queue_is_full(cs))
            {
              CS_TWO_LOG(
                  "the dram queue is full! we need delete a index in dram "
                  "queue,and insert new one!\n");
              RTE_LOG(DEBUG, USER1,
                      "the dram queue is full! we need delete a index in dram "
                      "queue,and insert new one!\n");
              dram_queue_insert_index = dram_queue_get_insert_index(cs);
              // CS_TWO_LOG("the dram queue insert index is
              // %d!\n",dram_queue_insert_index_tem);

              // the dram lru queue is full, if the last index has assemblede
              // succssfully, we delete it and pull new content into this index.
              // otherwise, we take content into a loop, we lookup the
              // (index-n)'s index, if (index-n)'s index.assemble_flag ==
              // COMPLETE we insert new content into (index-n)'s index

              bucket_of_replaced_chunk =
                  cs->dram_queue[dram_queue_insert_index].bucket;
              tab_of_replaced_chunk =
                  cs->dram_queue[dram_queue_insert_index].tab;
              if (cs->hash_table[bucket_of_replaced_chunk]
                      .entry[tab_of_replaced_chunk]
                      .assemble_flag == COMPLETE)
              {
                if ((cs->hash_table[bucket_of_replaced_chunk]
                         .entry[tab_of_replaced_chunk]
                         .dram_flag == CHUNK_STORE_IN_BOTH) ||
                    (cs->hash_table[bucket_of_replaced_chunk]
                         .entry[tab_of_replaced_chunk]
                         .dram_flag == CHUNK_STORE_IN_WRITE_DRAM) ||
                    (cs->hash_table[bucket_of_replaced_chunk]
                         .entry[tab_of_replaced_chunk]
                         .dram_flag == CHUNK_STORE_IN_FISK))
                {
                  CS_TWO_LOG(
                      "the dram_queue[%u] content had stored in write core,we "
                      "delete it in dram queue,"
                      "but it still store in fisk!the new chunk is %s \n",
                      dram_queue_insert_index, eid);
                  // when chunk is stored in write core, the dram flag has
                  // fixed, so we don't need to change it. in term of dram
                  // index, write core has also modify it so that the dram index
                  // indicate the dram index in the write core lru queue
                  // cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_flag
                  // = CHUNK_STORE_IN_FISK;
                  // cs->hash_table[bucket_of_replaced_chunk].entry[tab_of_replaced_chunk].dram_index
                  // = 0;
                }
                else if (cs->hash_table[bucket_of_replaced_chunk]
                             .entry[tab_of_replaced_chunk]
                             .dram_flag == CHUNK_STORE_IN_DRAM)
                {
                  CS_TWO_LOG(
                      "unexcepted situation! dram flag indicate this chunk had "
                      "assembled in LRU successfully,but it hasn't write in "
                      "file system until now");

                  cs->hash_table[bucket_of_replaced_chunk]
                      .entry[tab_of_replaced_chunk]
                      .dram_flag = CHUNK_IS_WRITTING;
                  cs->hash_table[bucket_of_replaced_chunk]
                      .entry[tab_of_replaced_chunk]
                      .dram_index = 0;
                }
                else if (cs->hash_table[bucket_of_replaced_chunk]
                             .entry[tab_of_replaced_chunk]
                             .dram_flag == CHUNK_IS_WRITTING)
                {
                  CS_TWO_LOG(
                      "chunk is writting!we delete it in worker core dram "
                      "lru!\n");
                  cs->hash_table[bucket_of_replaced_chunk]
                      .entry[tab_of_replaced_chunk]
                      .dram_index = 0;
                }
              }
              else if (cs->hash_table[bucket_of_replaced_chunk]
                           .entry[tab_of_replaced_chunk]
                           .assemble_flag == NOT_COMPLETE)
              {
                CS_TWO_LOG(
                    "the dram_queue[%u] content didn't assembled,may drop had "
                    "happened ,we delete it in dram queue,"
                    "the new chunk is %s \n",
                    dram_queue_insert_index, eid);
                cs->hash_table[bucket_of_replaced_chunk]
                    .entry[tab_of_replaced_chunk]
                    .dram_flag = CHUNK_JUST_IN_HASH;
                cs->hash_table[bucket_of_replaced_chunk]
                    .entry[tab_of_replaced_chunk]
                    .dram_index = 0;
              }

              create_dlink(cs, dram_queue_insert_index);
              dlink_insert(FIRST_NODE_INDEX, 0, SIZE_OF_ONE_CHUNK, cs,
                           dram_queue_insert_index);
              node_count = dlink_size(
                  cs->dram_queue[dram_queue_insert_index].node_count);
            }
            else
            {
              dram_queue_insert_index = dram_queue_get_insert_index(cs);
              create_dlink(cs, dram_queue_insert_index);
              dlink_insert(FIRST_NODE_INDEX, 0, SIZE_OF_ONE_CHUNK, cs,
                           dram_queue_insert_index);
              node_count = dlink_size(
                  cs->dram_queue[dram_queue_insert_index].node_count);
            }

            if (likely(update_chunk_assemble_dlink_info_by_copy(
                           cs, offset, dram_queue_insert_index, payload,
                           payload_len,
                           node_count) == PACKET_COPY_TO_DRAM_QUE))
            {
              // Associate this segment with this entry in hash table
              cs->hash_table[bucket].entry[tab].busy = 1;
              cs->hash_table[bucket].entry[tab].dram_flag = 0;
              cs->hash_table[bucket].entry[tab].assemble_flag = NOT_COMPLETE;
              cs->hash_table[bucket].entry[tab].dram_index =
                  dram_queue_insert_index;

              cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len = 1;
              // tem_chunk_len means that the recent received packet num of
              // chunk
              strcpy(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                     eid);

              // Associate this chunk with the dram queue. Packet pool index
              // will be associated afterwards.
              cs->dram_queue[dram_queue_insert_index].req_cnt = 1;
              cs->dram_queue[dram_queue_insert_index].bucket = bucket;
              cs->dram_queue[dram_queue_insert_index].tab = tab;

              // CS_TWO_LOG("First Packet of the chunk , the eid is %s!\n DRAM
              // Index %u \n", eid, dram_queue_insert_index);
            }
            else
            {
              // This code can not be reached if we set the packet buffer number
              // of packet pool carefully.
              CS_TWO_WARN(
                  "Insert first chunk, no available dram packet buffer \n");
              rte_exit(EXIT_FAILURE,
                       "lcore_id:%u, insert first chunk, no available dram "
                       "packet buffer for this chunk! \n",
                       rte_lcore_id());
              // return 0;
            }
            return 0;
          }

          if (unlikely(cs->hash_table[bucket].entry[tab].assemble_flag ==
                       COMPLETE))
          {
            CS_TWO_WARN(
                "wrong situaion!after looking up, this chunk should not be "
                "assembled complete, but the flag indicate this chunk "
                "assembled already!\n");
            return 0;
          }
          else if (likely(cs->hash_table[bucket].entry[tab].assemble_flag ==
                          NOT_COMPLETE))
          {
            dram_queue_index_from_entry =
                cs->hash_table[bucket].entry[tab].dram_index;
            node_count = dlink_size(
                cs->dram_queue[dram_queue_index_from_entry].node_count);

            // CS_TWO_LOG("Insert rest packet of chunk on dram index %u \n",
            // dram_queue_index_from_entry);
            ret = update_chunk_assemble_dlink_info_by_copy(
                cs, offset, dram_queue_index_from_entry, payload, payload_len,
                node_count);
            if (unlikely(ret == CHUNK_ASSEMBLE_SUCCESS))
            {
              // CS_TWO_LOG("push a packet of Chunk into DRAM, DRAM Index
              // %u,\n\n", dram_queue_index_from_entry);

              cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len++;

              // CS_TWO_LOG("this is a chunk total len: %u\n", chunk_total_len);
              // CS_TWO_LOG("this is a tem len: %u\n",
              // cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len);

              // CS_TWO_LOG("the chunk(%s) has been assembled,we push it to the
              // write core!\n", eid); RTE_LOG(DEBUG, USER1, "the chunk has been
              // assemble,the eid is %s!\n,the bucket is %d!\n ", eid, bucket);

              cs->hash_table[bucket].entry[tab].assemble_flag = COMPLETE;
              cs->hash_table[bucket].entry[tab].dram_flag = CHUNK_STORE_IN_DRAM;
              push_chunk_to_other_core(shm_message_pool, shm_ring_queue, cs,
                                       dram_queue_index_from_entry, msg,
                                       lcore_id);
            }
            else if (likely(ret == PACKET_COPY_TO_DRAM_QUE))
            {
              cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len++;
              CS_TWO_LOG("chunk has not assemble, we continue proess packet\n");
            }
            else if (ret == PACKET_ALREADY_EXIST)
            {
              CS_TWO_LOG("this packet has already arrived!\n");
            }
            return 0;
          }
        }
        else
        {
          // This hash table entry is occupied and the hash value of this chunk
          // is not equal to the existed one in this entry. In this case, we
          // need to iterate the bucket continue.
          CS_TWO_LOG(
              "hash[%u].entry[%u]_eid isn't equal to received eid,we lookup "
              "for next entry!\n",
              bucket, tab);
          continue;
        }
      }
    }
    // No available entry in current bucket, linear probing to solve collision
    bucket = (bucket + 1) % cs->hash_table_num_buckets;
  }

  return -ENOSPC;
}

int8_t cs_two_insert_with_hash(struct rte_mempool *shm_message_pool,
                               struct rte_ring *shm_ring_queue, uint32_t offset,
                               uint32_t payload_len, cs_two_t *cs,
                               char *payload, char *eid, uint32_t bucket_num_for_cs_two)
{
  return __cs_two_insert_with_hash(shm_message_pool, shm_ring_queue, offset,
                                   payload_len, cs, payload, eid, bucket_num_for_cs_two);
}

static inline uint8_t __cs_two_lookup_with_hash(
    struct rte_mempool *shm_message_pool, struct rte_ring *send_ring_to_tx,
    struct rte_ring *worker_to_write_ring, cs_two_t *cs, char *eid,
    struct rte_mbuf *mbuf, uint32_t bucket_num_for_cs_two)
{
  // if( rte_lcore_id() != 1 ){
  //     return NULL;
  // }

  uint32_t bucket, hash_bucket;
  uint8_t tab;
  uint32_t dram_queue_index; /**< used to record index on dram queue  */
  uint8_t exit_flag = 0;

  struct chunk_msg_desc *a_chunk_msg_desc_to_tx =
      NULL; /**< used to send chunk to the tx core when the request hit in the
               DRAM */
  struct chunk_msg_desc *a_chunk_msg_desc_to_write =
      NULL; /**< or used to send a a request msg to write core when the chunk is
               stored on fisk. */

  bucket =
      get_bucket_from_hex_eid(bucket_num_for_cs_two, eid); /**< Get index of corresponding bucket */
  CS_TWO_LOG("the bucket calcuatd by eid is %d\n", bucket);
  hash_bucket = bucket;

  unsigned lcore_id;

  lcore_id = rte_lcore_id();

  while (1)
  {
    if (exit_flag == 1)
    {
      break;
    }

    for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++)
    {
      if (likely(cs->hash_table[bucket].entry[tab].busy == 0))
      {
        if (bucket == hash_bucket)
        {
          continue;
        }
        else
        {
          // In this case, we iterate a bucket, but this element is null, which
          // indicates that the element must not exist, otherwise this element
          // must be occupied in the inserting process. This can not guarantee
          // that this element does not exist as cache replacement occurs
          exit_flag = 1;
          break;
        }
      }

      if (strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                 eid) != 0)
      {
        continue;
      }

      CS_TWO_LOG("the dram_flag is %d!\n",
                 cs->hash_table[bucket].entry[tab].dram_flag);

      if (cs->hash_table[bucket].entry[tab].dram_flag == CHUNK_JUST_IN_HASH)
      {
        CS_TWO_LOG(
            "this chunk has not assembled successfully, but it had expeled "
            "from worker dram lru! so cache not hit\n");
        return CACHE_NO_HIT;
      }
      // When this chunk is stored on fisk, which means its had been assembled
      // ,we send a msg to write core. and notify write core send chunk to tx
      // core. then we don't need a feedback msg.
      if ((cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_FISK) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_WRITE_DRAM) ||
          (cs->hash_table[bucket].entry[tab].dram_flag ==
           CHUNK_STORE_IN_BOTH))
      {
        if (cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE)
        {
          CS_TWO_LOG(
              "error situation, the chunk should have been stored in write "
              "core with assembled state,but it's not!");
          return CACHE_NO_HIT;
        }

        rcv_inf inf;
        if (rcv_parse(mbuf, &inf) != 0)
        {
          CS_TWO_LOG("Error parsing request packet.\n");
          return CACHE_NO_HIT;
        }
      //  CS_TWO_WARN("%s:%d rcv_inf.ack_n = %d\n", __FILE__, __LINE__,
      //              inf.ack_n);
        unsigned i;
        for (i = 0U; i < inf.ack_n; i++)
        {
          /* chunk is stored in fisk */
          if (rte_mempool_get(shm_message_pool,
                              (void **)&a_chunk_msg_desc_to_write) < 0)
          {
            CS_TWO_WARN(
                "Not enough entries in the schedule mempool on message "
                "packet pool for make up a msg to write on socket:%u "
                "\n",
                rte_socket_id());
          }

          /* Put this message on the ring, so that write IO core can
           * receive it */
          if (a_chunk_msg_desc_to_write != NULL)
          {
            a_chunk_msg_desc_to_write->io_type = REQUEST_IO_READ;
            char hex[41] = {0};
            char_array_2_hex_string(hex, inf.EID, 20);
            memcpy(a_chunk_msg_desc_to_write->chunk_eid, hex, 41);
            rte_memcpy(&a_chunk_msg_desc_to_write->mbuf, mbuf,
                       sizeof(struct rte_mbuf));
            a_chunk_msg_desc_to_write->offset = inf.offset[i];
            a_chunk_msg_desc_to_write->size = inf.size[i];
            a_chunk_msg_desc_to_write->chunk_size = tab;
            CS_TWO_LOG("%s:%d inf.size = %d\n", __FILE__, __LINE__,
                       inf.size[i]);
            if (rte_ring_enqueue(worker_to_write_ring,
                                 a_chunk_msg_desc_to_write) < 0)
            {
              CS_TWO_WARN(
                  "Not enough room in the ring to enqueue on socket:%u "
                  "\n",
                  rte_socket_id());

              rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_write);
            }
            else
            {
              CS_TWO_LOG(
                  "chunk is stored in write core and a request is sent "
                  "to write core! \n");
            }
          }
        }

#ifdef enable_disable
        /* chunk is stored in fisk */
        if (rte_mempool_get(shm_message_pool,
                            (void **)&a_chunk_msg_desc_to_write) < 0)
        {
          CS_TWO_WARN(
              "Not enough entries in the schedule mempool on message packet "
              "pool for make up a msg to write on socket:%u \n",
              rte_socket_id());
        }

        /* Put this message on the ring, so that write IO core can receive it
        /*/
        if (a_chunk_msg_desc_to_write != NULL)
        {
          a_chunk_msg_desc_to_write->io_type = REQUEST_IO_READ;
          strcpy(a_chunk_msg_desc_to_write->chunk_eid, eid);
          rte_memcpy(&a_chunk_msg_desc_to_write->mbuf, mbuf,
                     sizeof(struct rte_mbuf));
          a_chunk_msg_desc_to_write->chunk_size = tab;
          if (rte_ring_enqueue(worker_to_write_ring,
                               a_chunk_msg_desc_to_write) < 0)
          {
            CS_TWO_WARN(
                "Not enough room in the ring to enqueue on socket:%u \n",
                rte_socket_id());

            rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_write);
          }
          else
          {
            CS_TWO_LOG(
                "chunk is stored in write core and a request is sent to "
                "write core! \n");
          }
          // This can lead to false positive if the hash value of the
          // requested chunk equals to the value recorded
        }
#endif
        return CACHE_HIT_ON_FISK;
      } // chunk is stored in DRAM
#ifndef ENABLE_DRAM
      else
      {
        return CACHE_HIT_ON_FISK;
      }
#else
      else if (cs->hash_table[bucket].entry[tab].dram_flag ==
               CHUNK_STORE_IN_DRAM)
      {
        CS_TWO_LOG(
            "[lcore:%d]we have this eid, we first check whether its assembled! "
            "from DRAM\n",
            lcore_id);
        if (cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE)
        {
          CS_TWO_LOG(
              "[lcore:%d]wrong situation! chunk should has been assembled!but "
              "it's not! request can not hit\n",
              lcore_id);
          return CACHE_NO_HIT;
        }
        else if (cs->hash_table[bucket].entry[tab].assemble_flag ==
                 COMPLETE)
        {
          CS_TWO_LOG(
              "[lcore:%d]chunk stored in worker DRAM, we put it to tx core!\n",
              lcore_id);
        }

        dram_queue_index = cs->hash_table[bucket].entry[tab].dram_index;

        cs->dram_queue[dram_queue_index].req_cnt += 1;
        // This chunks will be moved to the head of the dram queue first based
        // on LRU strategy.
        dram_queue_update_by_visit_index(cs, dram_queue_index);
        CS_TWO_LOG("update the dram queue because of this chunk request!\n");

        if (rte_mempool_get(shm_message_pool,
                            (void **)&a_chunk_msg_desc_to_tx) < 0)
        {
          CS_TWO_WARN(
              "Not enough entries in the schedule mempool on message packet "
              "pool on socket:%u \n",
              rte_socket_id());
        }

        /* Put this message on the ring, so that tx  core can receive it */
        if (a_chunk_msg_desc_to_tx != NULL)
        {
          a_chunk_msg_desc_to_tx->io_type = REQUEST_IO_READ;
          strcpy(a_chunk_msg_desc_to_tx->chunk_eid,
                 cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid);
          a_chunk_msg_desc_to_tx->chunk_size =
              SIZE_OF_ONE_CHUNK; // offst and length should be considered
                                 // further
          rte_memcpy(
              a_chunk_msg_desc_to_tx->chunk,
              cs->dram_queue[dram_queue_index].dram_packet_pool_chunk_addr,
              SIZE_OF_ONE_CHUNK);
          rte_memcpy(&a_chunk_msg_desc_to_tx->mbuf, mbuf,
                     sizeof(struct rte_mbuf));
        }
        if (rte_ring_enqueue(send_ring_to_tx, a_chunk_msg_desc_to_tx) < 0)
        {
          CS_TWO_WARN("Not enough room in the ring to enqueue on socket:%u \n",
                      rte_socket_id());

          rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_tx);
          return -1;
        }
        CS_TWO_LOG("[lcore:%d]we have pushed the chunk to tx core!\n",
                   lcore_id);
        return CACHE_HIT_ON_DRAM;
      }
      else if (cs->hash_table[bucket].entry[tab].dram_flag ==
               CHUNK_IS_WRITTING)
      {
        if (cs->hash_table[bucket].entry[tab].assemble_flag == NOT_COMPLETE)
        {
          CS_TWO_LOG(
              "error situation, the chunk should have been assembled! but it's "
              "not!");
          return CACHE_NO_HIT;
        }

        /* chunk is stored in fisk */
        if (rte_mempool_get(shm_message_pool,
                            (void **)&a_chunk_msg_desc_to_write) < 0)
        {
          CS_TWO_WARN(
              "Not enough entries in the schedule mempool on message packet "
              "pool for make up a msg to write on socket:%u \n",
              rte_socket_id());
        }

        /* Put this message on the ring, so that write IO core can receive it */
        if (a_chunk_msg_desc_to_write != NULL)
        {
          a_chunk_msg_desc_to_write->io_type = REQUEST_IO_READ;
          strcpy(a_chunk_msg_desc_to_write->chunk_eid, eid);
          a_chunk_msg_desc_to_write->chunk_size = tab;
          rte_memcpy(&a_chunk_msg_desc_to_write->mbuf, mbuf,
                     sizeof(struct rte_mbuf));

          if (rte_ring_enqueue(worker_to_write_ring,
                               a_chunk_msg_desc_to_write) < 0)
          {
            CS_TWO_WARN(
                "Not enough room in the ring to enqueue on socket:%u \n",
                rte_socket_id());

            rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_write);
          }
          else
          {
            CS_TWO_LOG(
                "this chunk state is writting to write core, so we put a "
                "request is sent to write core! \n");
          }
          // This can lead to false positive if the hash value of the requested
          // chunk equals to the value recorded
          return CACHE_HIT_ON_FISK;
        }
      }
#endif
    }

    bucket = (bucket + 1) % cs->hash_table_num_buckets;
  }

  // We have iterated the designated bucket, but still can not find a matched
  // item.
  //CS_TWO_WARN(
  //    "We have iterated the designated bucket, but still can not find a "
  //    "matched item chunk. \n");
  return CACHE_NO_HIT;
}

uint8_t cs_two_lookup_with_hash(struct rte_mempool *shm_message_pool,
                                struct rte_ring *send_ring_to_tx,
                                struct rte_ring *worker_to_write_ring,
                                cs_two_t *cs, char *eid,
                                struct rte_mbuf *mbuf,
                                uint32_t bucket_num_for_cs_two)
{
  return __cs_two_lookup_with_hash(shm_message_pool, send_ring_to_tx,
                                   worker_to_write_ring, cs, eid, mbuf, bucket_num_for_cs_two);
}

static inline int8_t __cs_two_update_with_lru_in_write_by_data(
    cs_two_t *cs, cs_two_t *cs_worker, uint32_t bucket, char *payload,
    char *eid)
{
  // struct chunk_msg_desc *msg = NULL; /**< used to send a message to SSD IO
  // core when dram queue is full */
  uint32_t hash_bucket;

  uint8_t tab = 0;
  // uint32_t pool_index, j;
  // uint8_t  *packet;                     /**< point to real network packet */

  uint32_t dram_queue_insert_index = 0;
  // uint32_t dram_queue_insert_index_tem; /**< store the index value that will
  // be inserted on the dram queue */ uint32_t dram_queue_index_from_entry; /**<
  // store the dram queue index from an existed hash table entry */

  uint32_t bucket_of_replaced_chunk,
      tab_of_replaced_chunk; /**< tmp variable to record chunk that will be
                                replaced */
  // unsigned lcore_id;
  uint8_t exit_flag = 0;

  // lcore_id = rte_lcore_id();

  // uint64_t begin_rtc, end_rtc;
  // float    us_value;

  // printf("the bucket is %d\n", bucket);
  hash_bucket = bucket;

  while (1)
  {
    if (exit_flag == 1)
    {
      break;
    }
    if (dram_queue_is_full(cs))
    {
      CS_TWO_LOG(
          "the writer core dram queue is full! we need delete a index in dram "
          "queue,and insert new one!\n");
      dram_queue_insert_index = dram_queue_get_insert_index(cs);

      bucket_of_replaced_chunk = cs->dram_queue[dram_queue_insert_index].bucket;
      tab_of_replaced_chunk = cs->dram_queue[dram_queue_insert_index].tab;
      if (cs_worker->hash_table[bucket_of_replaced_chunk]
              .entry[tab_of_replaced_chunk]
              .dram_flag == CHUNK_STORE_IN_BOTH)
      {
        cs_worker->hash_table[bucket_of_replaced_chunk]
            .entry[tab_of_replaced_chunk]
            .dram_flag = CHUNK_STORE_IN_FISK;
        cs_worker->hash_table[bucket_of_replaced_chunk]
            .entry[tab_of_replaced_chunk]
            .dram_index = 0;
      }
      else if (cs_worker->hash_table[bucket_of_replaced_chunk]
                   .entry[tab_of_replaced_chunk]
                   .dram_flag == CHUNK_STORE_IN_WRITE_DRAM)
      {
        CS_TWO_LOG(
            "wrong situation,when chunk store work had been down, just store "
            "in write dram hardly happen!\n");
      }
    }
    else
    {
      dram_queue_insert_index = dram_queue_get_insert_index(cs);
    }

    //CS_TWO_WARN("the dram queue insert index in write core is %d\n",
    //        dram_queue_insert_index);
    for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++)
    {
      if (likely(cs_worker->hash_table[bucket].entry[tab].busy == 0))
      {
        if (bucket == hash_bucket)
        {
            continue;
        }
        else
        {
          // In this case, we iterate a bucket, but this element is null, which
          // indicates that the element must not exist, otherwise this element
          // must be occupied in the inserting process. This can not guarantee
          // that this element does not exist as cache replacement occurs
          exit_flag = 1;
          break;
        }
      }

      if (strcmp(cs_worker->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                 eid) != 0)
      {
        continue;
      }

      if (likely(copy_chunk_to_dram_lru_in_write(cs, dram_queue_insert_index,
                                                 payload) == 0))
      {
        // Associate this chunk with the dram queue. Packet pool index will be
        // associated afterwards.
        cs->dram_queue[dram_queue_insert_index].req_cnt = 1;
        cs->dram_queue[dram_queue_insert_index].bucket = bucket;
        cs->dram_queue[dram_queue_insert_index].tab = tab;
        cs_worker->hash_table[bucket].entry[tab].dram_flag =
            CHUNK_STORE_IN_WRITE_DRAM;
        cs_worker->hash_table[bucket].entry[tab].dram_index =
            dram_queue_insert_index;
        return tab;
      }
      else
      {
        // This code can not be reached if we set the packet buffer number of
        // packet pool carefully.
        CS_TWO_WARN(
            "Insert chunk to write lru queue, no available dram packet buffer "
            "\n");
        rte_exit(EXIT_FAILURE,
                 "lcore_id:%u, Insert chunk to write lru queue, no available "
                 "dram packet buffer for this chunk! \n",
                 rte_lcore_id());
        return -ENOSPC;
      }
    }
    bucket++;
  }
  return -ENOSPC;
}

int8_t cs_two_update_with_lru_in_write_by_data(cs_two_t *cs,
                                               cs_two_t *cs_worker,
                                               uint32_t bucket, char *payload,
                                               char *eid)
{
  return __cs_two_update_with_lru_in_write_by_data(cs, cs_worker, bucket,
                                                   payload, eid);
}

static inline uint8_t __cs_two_lookup_with_hash_in_write(
    struct rte_mempool *shm_message_pool, struct rte_ring *send_ring_to_tx,
    cs_two_t *cs, cs_two_t *cs_worker, uint8_t table, uint32_t bucket,
    char *eid, struct rte_mbuf *mbuf, uint32_t bucket_num_for_cs_two)
{
  struct chunk_msg_desc *a_chunk_msg_desc_to_tx =
      NULL; /**< used to send chunk to the tx core when the request hit in the
               DRAM */
  uint32_t writer_dram_queue_index;

  while (1)
  {
    if (strcmp(cs_worker->hash_table[bucket].entry[table].chunk_info->chunk_eid,
               eid) != 0)
    {
      CS_TWO_WARN("wrong situation, fatal error!eid different!");
      return CACHE_NO_HIT;
    }

    if (cs_worker->hash_table[bucket].entry[table].dram_flag ==
        CHUNK_STORE_IN_FISK)
    {
      if (cs_worker->hash_table[bucket].entry[table].assemble_flag ==
          NOT_COMPLETE)
      {
        CS_TWO_LOG(
            "error situation, the chunk should have been stored in write core "
            "with assembled state,but it's not!\n");
        return CACHE_NO_HIT;
      }
      if (dram_queue_is_full(cs))
      {
		writer_dram_queue_index = dram_queue_get_insert_index(cs);
        cs_worker->hash_table[bucket].entry[table].dram_index =
            writer_dram_queue_index;
        cs->dram_queue[writer_dram_queue_index].req_cnt += 1;
        cs->dram_queue[writer_dram_queue_index].bucket = bucket;
        cs->dram_queue[writer_dram_queue_index].tab = table;
        dram_queue_update_by_visit_index(cs, writer_dram_queue_index);

        return CACHE_HIT_ON_FISK;
      }
      else
      {
        CS_TWO_WARN(
            "wrong situation! write core lru queue should be full now!\n");
        return CACHE_NO_HIT;
      }

    } // chunk is stored in DRAM
    else if (cs_worker->hash_table[bucket].entry[table].dram_flag ==
             CHUNK_STORE_IN_WRITE_DRAM)
    {
      CS_TWO_LOG(
          "wrong situation,when chunk store work had been down, just store in "
          "write dram hardly happen!\n");
      return CACHE_NO_HIT;
    }
    else if (cs_worker->hash_table[bucket].entry[table].dram_flag ==
             CHUNK_STORE_IN_BOTH)
    {
      CS_TWO_LOG(
          "cache hit both in the dram and fisk, we put it to the tx core from "
          "write dram!\n");
      writer_dram_queue_index =
          cs_worker->hash_table[bucket].entry[table].dram_index;
      cs->dram_queue[writer_dram_queue_index].req_cnt += 1;
      cs->dram_queue[writer_dram_queue_index].bucket = bucket;
      cs->dram_queue[writer_dram_queue_index].tab = table;
      dram_queue_update_by_visit_index(cs, writer_dram_queue_index);
      if (rte_mempool_get(shm_message_pool, (void **)&a_chunk_msg_desc_to_tx) <
          0)
      {
        CS_TWO_WARN(
            "Not enough entries in the schedule mempool on message packet pool "
            "on socket:%u \n",
            rte_socket_id());
      }
      /* Put this message on the ring, so that tx  core can receive it */
      if (a_chunk_msg_desc_to_tx != NULL)
      {
        a_chunk_msg_desc_to_tx->io_type = NOTIFY_IO_READ_FINISH;
        strcpy(a_chunk_msg_desc_to_tx->chunk_eid, eid);
        a_chunk_msg_desc_to_tx->chunk_size =
            SIZE_OF_ONE_CHUNK; // offst and length should be considered further
        rte_memcpy(
            a_chunk_msg_desc_to_tx->chunk,
            cs->dram_queue[writer_dram_queue_index].dram_packet_pool_chunk_addr,
            SIZE_OF_ONE_CHUNK);
        rte_memcpy(&a_chunk_msg_desc_to_tx->mbuf, mbuf,
                   sizeof(struct rte_mbuf));
      }
      if (rte_ring_enqueue(send_ring_to_tx, a_chunk_msg_desc_to_tx) < 0)
      {
        CS_TWO_WARN("Not enough room in the ring to enqueue on socket:%u \n",
                    rte_socket_id());

        rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_tx);
        return -1;
      }
      // CS_TWO_LOG("[lcore:%d]we have pushed the chunk to tx core!\n",
      // lcore_id);
      return CACHE_HIT_ON_DRAM;
    }
  }
}

uint8_t cs_two_lookup_with_hash_in_write(struct rte_mempool *shm_message_pool,
                                         struct rte_ring *send_ring_to_tx,
                                         cs_two_t *cs, cs_two_t *cs_worker,
                                         uint8_t table, uint32_t bucket,
                                         char *eid, struct rte_mbuf *mbuf,
                                         uint32_t bucket_num_for_cs_two)
{
  return __cs_two_lookup_with_hash_in_write(shm_message_pool, send_ring_to_tx,
                                            cs, cs_worker, table, bucket, eid,
                                            mbuf, bucket_num_for_cs_two);
}

static inline uint8_t __cs_two_recover_with_hash(struct rte_mempool *shm_message_pool,
                                                 struct rte_ring *worker_to_write_ring,
                                                 cs_two_t *cs, char *eid, uint32_t bucket_num_for_cs_two)
{
  uint32_t bucket;
  uint8_t tab;
  uint32_t dram_queue_index; /**< used to record index on dram queue  */
  uint8_t exit_flag = 0;

  // struct chunk_msg_desc *a_chunk_msg_desc_to_tx = NULL; /**< used to send
  // chunk to the tx core when the request hit in the DRAM */ struct
  struct chunk_msg_desc *a_chunk_msg_desc_to_write = NULL; /**< or used to send a a
  // request msg to write core when the chunk is stored on fisk. */

  bucket =
      get_bucket_from_hex_eid(bucket_num_for_cs_two, eid); /**< Get index of corresponding bucket */
  CS_TWO_LOG("the bucket calcuatd by eid is %d\n", bucket);
  // hash_bucket = bucket;

  unsigned lcore_id;

  lcore_id = rte_lcore_id();

  while (1)
  {
    if (exit_flag == 1)
    {
      break;
    }

    for (tab = 0; tab < ENTRY_NUM_OF_ONE_BUCKET; tab++)
    {
      if (likely(cs->hash_table[bucket].entry[tab].busy == 0))
      {
        // Associate this chunk with this entry in hash table
        cs->hash_table[bucket].entry[tab].busy = 1;
        cs->hash_table[bucket].entry[tab].dram_flag = CHUNK_STORE_IN_FISK;
        cs->hash_table[bucket].entry[tab].assemble_flag = COMPLETE;
        cs->hash_table[bucket].entry[tab].dram_index =
            -1; // doesn't exist in dram

        cs->hash_table[bucket].entry[tab].chunk_info->tem_chunk_len =
            0; // doesn't need this
        strcpy(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid, eid);
        CS_TWO_LOG("the chunk is recoveried!\n");

        //send register request to writer core
        if (rte_mempool_get(shm_message_pool,
                            (void **)&a_chunk_msg_desc_to_write) < 0)
        {
          CS_TWO_WARN(
              "Not enough entries in the schedule mempool on message packet "
              "pool for make up a msg to write on socket:%u \n",
              rte_socket_id());
        }

        if (a_chunk_msg_desc_to_write != NULL)
        {
          a_chunk_msg_desc_to_write->io_type = REQUEST_REGISTER;
          memcpy(a_chunk_msg_desc_to_write->chunk_eid, eid, 41);

          if (rte_ring_enqueue(worker_to_write_ring,
                               a_chunk_msg_desc_to_write) < 0)
          {
            CS_TWO_WARN(
                "Not enough room in the ring to enqueue on socket:%u "
                "\n",
                rte_socket_id());

            rte_mempool_put(shm_message_pool, a_chunk_msg_desc_to_write);
          }
          else
          {
            CS_TWO_LOG(
                "chunk is stored in write core and a request is sent "
                "to write core! \n");
          }
        }

        return 0;
      }

      if (strcmp(cs->hash_table[bucket].entry[tab].chunk_info->chunk_eid,
                 eid) != 0)
      {
        continue;
      }

      else
      {
        CS_TWO_LOG("the chunk is already in cs_two!\n");
        return 0;
      }
    }

    bucket = (bucket + 1) % cs->hash_table_num_buckets;
  }
  // We have iterated the designated bucket, but still can not find a matched
  // item.
  CS_TWO_WARN("We can not recover this chunk. \n");
  return -1;
}

uint8_t cs_two_recover_with_hash(struct rte_mempool *shm_message_pool,
                                                 struct rte_ring *worker_to_write_ring,
                                                 cs_two_t *cs, char *eid, uint32_t bucket_num_for_cs_two)
{
  return __cs_two_recover_with_hash(shm_message_pool, worker_to_write_ring, cs, eid, bucket_num_for_cs_two);
}


uint8_t *get_chunk_buf(void* pointer, uint32_t size)//for seadp client
{
  uint8_t *temp = (uint8_t *)rte_malloc(NULL,size,0);
  return temp;
}
void free_chunk_buf(void* pointer, uint8_t *chunk, uint32_t size)//for seadp client
{
  if(chunk != NULL)
    rte_free(chunk);
}