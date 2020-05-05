/*
Author: YH Li
Build a dedicated lcore to implement file system IO operation
*/

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_malloc.h>

//#include "init.h"
#include "writer_core.h"

#define WRITE_LOG(...) RTE_LOG(DEBUG, USER1, "[WRITE_IOG]: " __VA_ARGS__)
#define WRITE_WARN(...) RTE_LOG(WARNING, USER1, "[WRITE_WARN]: " __VA_ARGS__)

/*function operation:
        output the path of a chunk should be put in,
        its like "/data/f1_i/f2_j" while 0<=i,j<128
*/
static int lookup_path(char *chunk_eid, char *eid_path)
{
  char res1[10], res2[10] = {0};
  unsigned int num_front_four_bytes, num_last_four_bytes = 0;
  char a[5], b[5] = {0};
  if (chunk_eid == NULL)
  {
    printf("receive an unknown eid\n");
    return -1;
  }

  strncpy(a, chunk_eid, 4);
  strncpy(b, chunk_eid + EID_LEN_HEX - 4, 4);
  sscanf(a, "%x", &num_front_four_bytes);
  sscanf(b, "%x", &num_last_four_bytes);
  // WRITE_LOG("eid前2Byte是：%d\n", num_front_four_bytes);
  // WRITE_LOG("eid后2Byte是：%d\n", num_last_four_bytes);
  sprintf(res1, "%d", num_front_four_bytes % PRIMARY_FOLDER_NUM);
  sprintf(res2, "%d", num_last_four_bytes % SECONDARY_FOLDER_NUM);
  strcpy(eid_path,
         FILESYSTEM_PATH_NAME); // strcpy function will cover old information
  strcat(eid_path, "/f1_");
  strcat(eid_path, res1);
  strcat(eid_path, "/f2_");
  strcat(eid_path, res2);
  strcat(eid_path, "/");
  strcat(eid_path, chunk_eid);
  // WRITE_LOG("eid_path是：%s\n", eid_path);
  return 0;
}

static int is_file_exist(const char *file_path)
{
  if (file_path == NULL)
    return -1;
  if (access(file_path, F_OK) == 0)
    return 0;
  return -1;
}

static int64_t read_file(uint8_t *buffer, const char *filename, int64_t offset,
                         int64_t size)
{
  if (!filename || !buffer || offset < 0 || size <= 0)
  {
    return -99;
  }
  FILE *fp = fopen(filename, "r");
  if (!fp)
  { // Error opening file.
    return -1;
  }
  if (fseek(fp, 0, SEEK_END)) {  // Seek failed.
    fclose(fp);
    return -3;
  }
  int64_t fsize = ftell(fp);
  if ((offset < 0) || (size < 0) || (offset > fsize) ||
      (offset + size > fsize))
  { // Request out of range.
    fclose(fp);
    return -2;
  }
  if (fseek(fp, offset, SEEK_SET))
  { // Seek failed.
    fclose(fp);
    return -3;
  }
  long rsize = (long)fread(buffer, 1, size, fp);
  if (rsize < size)
  { // EOF reached before requested size.
    fclose(fp);
    return -4;
  }
  fclose(fp);
  return fsize;
}

int fs_io_loop(__attribute__((unused)) void *arg)
{
  // self
  struct chunk_msg_desc *a_chunk_msg_desc =
      NULL; /**< used to send a message to writer core when dram queue is full.
             */
  struct chunk_msg_desc *a_chunk_msg_desc_to_tx =
      NULL; /**< used to send a message to tx core from writer core. */
  struct chunk_msg_desc *a_register_msg_to_tx =
      NULL; /**< used to send a register msg to tx core from writer core */
  struct register_desc *register_desc = NULL;
  register_desc = (struct register_desc *)rte_malloc("TMP_MSG_REG",
                                                     sizeof(register_desc), 0);
  char *fs_path_for_eid = (char *)rte_malloc(
      "FS_PATH", sizeof(char) * 60,
      0); /**<used to storage a path corrosponding to a chunk eid */
  FILE *fp = NULL;
  struct rte_mempool *pool = NULL;

  unsigned lcore_id, socket_id;

  struct app_lcore_params *conf;
  struct app_lcore_params *conf_tx = NULL;
  struct app_lcore_params *conf_worker = NULL;

  char eid_from_worker_msg[EID_LEN_HEX + 1];
  int8_t ret;
  int8_t table;
  int writen_num = 0;
  uint32_t bucket;
  uint32_t dram_write_lru_index_tmp;

  // store temp info for a_notify_desc
  char chunk_temp[SIZE_OF_ONE_CHUNK] = {0};
  // char chunk_temp[] how to store chunk?
  struct rte_ring *recv_ring_from_worker;
  struct rte_ring *send_ring_to_tx;

  // NUMA node0 CPU(s):     0,2,4,6,8,10,12,14,16,18,20,22
  // NUMA node1 CPU(s):     1,3,5,7,9,11,13,15,17,19,21,23

  lcore_id = rte_lcore_id();
  printf("the no %d writer is start!\n",lcore_id); 
  socket_id = rte_lcore_to_socket_id(
      lcore_id); // use to get ring and mempool with tx core

  conf_worker = &lcore_conf[lcore_id - WORKER_WRITER_ID_DIFFER_NUM];
  if (socket_id == 0)
  {
    conf_tx = &lcore_conf[app_conf.lcore_configuration.tx_1];
  }
  else if (socket_id == 1)
  {
    conf_tx = &lcore_conf[app_conf.lcore_configuration.tx_2];
  } else {
    return -1;
  }

  conf = &lcore_conf[lcore_id];
  send_ring_to_tx = conf_tx->send_ring;
  recv_ring_from_worker = conf->recv_ring;
  pool = conf->shm_message_pool;
  uint32_t bucket_num_for_cs_two = app_conf.bucket_num_for_cs_two;

  while (1)
  {
    // get message from recv_ring
    if (rte_ring_dequeue(recv_ring_from_worker, (void **)&a_chunk_msg_desc) < 0)
    {
      continue;
    }
    else
    {
      bucket = get_bucket_from_hex_eid(bucket_num_for_cs_two, a_chunk_msg_desc->chunk_eid);
      WRITE_LOG("%s:%d bucket = %08x\n", __FILE__, __LINE__, bucket);
      // WRITE_LOG("\n");
      // Enter different processing flow according to io type
      if (a_chunk_msg_desc->io_type == REQUEST_IO_WRITE) 
      {
        ret = cs_two_update_with_lru_in_write_by_data(
            conf->cs_two, conf_worker->cs_two, bucket, a_chunk_msg_desc->chunk,
            a_chunk_msg_desc->chunk_eid);
        strcpy(eid_from_worker_msg, a_chunk_msg_desc->chunk_eid);
        WRITE_LOG("%s:%d entry = %02x\n", __FILE__, __LINE__, ret);
        if (ret == -ENOSPC)
        {
          WRITE_LOG(
              "cs two update with lru in write by data fail! we put into fisk "
              "directly!\n");
          if (lookup_path(eid_from_worker_msg, fs_path_for_eid) == 0)
          {
            fp = fopen(fs_path_for_eid,
                       "w+"); // if file already exists, it will be updated
            if (fp) {
              writen_num =
                  fwrite(a_chunk_msg_desc->chunk, SIZE_OF_ONE_CHUNK, 1, fp);
              fclose(fp);
            }

            // TODO: construct write finish notify
            if (writen_num == 0)
            {
              WRITE_LOG(
                  "write core write into fisk fail! \n"); // write operation
                                                          // failed
            }
            else
            {
              RTE_LOG(ERR, USER1, "Cached: %s\n", fs_path_for_eid);
              WRITE_LOG(
                  "finish writting chunk into filesystem,then we register it! "
                  "eid is %s\n",
                  eid_from_worker_msg);
              conf->stats.nb_chunk_write_to_ssd += 1;
              RTE_LOG(DEBUG, USER1,
                      "finish writting chunk(%s) into filesystem!we then "
                      "register it! \n",
                      eid_from_worker_msg);

              conf_worker->cs_two->hash_table[bucket].entry[ret].dram_flag =
                  CHUNK_STORE_IN_FISK;

              // RTE_LOG(DEBUG, USER1, "[WORKER]: feedback:\n chunk has stored
              // in write core,we update the hash table!\n ");
              conf_worker->stats.chunk_assembled += 1;
              RTE_LOG(DEBUG, USER1,
                      "[LCORE_%u]: the num of the assembled chunk is %d!\n",
                      lcore_id - 12, conf_worker->stats.chunk_assembled);

              while (1)
              {
                if (rte_mempool_get(pool, (void **)&a_register_msg_to_tx) < 0)
                {
                  WRITE_WARN(
                      "Not enough entries in the mempool on message packet "
                      "pool on socket:%u \n",
                      rte_socket_id());
                }
                else
                {
                  break;
                }
              }
              // construct a register msg (send to tx core)
              strcpy(a_register_msg_to_tx->chunk_eid, eid_from_worker_msg);
              a_register_msg_to_tx->io_type = REQUEST_REGISTER;

              // memset(&a_chunk_msg_desc->mbuf, 0, sizeof(struct rte_mbuf));
              a_register_msg_to_tx->chunk_size = 20 + 4 + 1 + 4 + 1;

              // rte_memcpy(a_register_msg_to_tx->chunk,register_desc,sizeof(struct
              // register_desc)); printf(i);

              if (rte_ring_enqueue(send_ring_to_tx, a_register_msg_to_tx) < 0)
              {
                WRITE_WARN(
                    "Not enough room in the ring to enqueue on socket:%u \n",
                    rte_socket_id());
                rte_mempool_put(pool, a_register_msg_to_tx);
              }
            }
          }
          else // consider using a special folder to place these strange
               // chunks
          {
            WRITE_WARN("Receive an unknown request with wrong chunk eid!\n");
            // TODO: construct write failed notify
          }
        }
        else
        {
          rte_mempool_put(pool, a_chunk_msg_desc);
          dram_write_lru_index_tmp =
              conf_worker->cs_two->hash_table[bucket].entry[ret].dram_index;

          if (lookup_path(eid_from_worker_msg, fs_path_for_eid) == 0)
          {
            fp = fopen(fs_path_for_eid,
                       "w+"); // if file already exists, it will be updated
            if (!fp)
            {
              WRITE_LOG("%s:%d %s open failed\n", __FILE__, __LINE__,
                        fs_path_for_eid);
              continue;
            }

            writen_num =
                fwrite(conf->cs_two->dram_queue[dram_write_lru_index_tmp]
                           .dram_packet_pool_chunk_addr,
                       SIZE_OF_ONE_CHUNK, 1, fp);
            fclose(fp);

            // TODO: construct write finish notify
            if (writen_num == 0)
            {
              WRITE_LOG(
                  "write core write into fisk fail! \n"); // write operation
                                                          // failed
            }
            else
            {
              RTE_LOG(ERR, USER1, "Cached: %s\n", fs_path_for_eid);
              WRITE_LOG(
                  "finish writting chunk into filesystem,then we register it! "
                  "eid is %s\n",
                  eid_from_worker_msg);
              conf->stats.nb_chunk_write_to_ssd += 1;
              RTE_LOG(DEBUG, USER1,
                      "finish writting chunk(%s) into filesystem!we then "
                      "register it! \n",
                      eid_from_worker_msg);

              conf_worker->cs_two->hash_table[bucket].entry[ret].dram_flag =
                  CHUNK_STORE_IN_BOTH;
              // RTE_LOG(DEBUG, USER1, "[WORKER]: feedback:\n chunk has stored
              // in write core,we update the hash table!\n ");
              conf_worker->stats.chunk_assembled += 1;
              RTE_LOG(DEBUG, USER1,
                      "[LCORE_%u]: the num of the assembled chunk is %d!\n",
                      lcore_id - 12, conf_worker->stats.chunk_assembled);

              while (1)
              {
                if (rte_mempool_get(pool, (void **)&a_register_msg_to_tx) < 0)
                {
                  WRITE_WARN(
                      "Not enough entries in the mempool on message packet "
                      "pool on socket:%u \n",
                      rte_socket_id());
                }
                else
                {
                  break;
                }
              }
              // construct a register msg (send to tx core)
              strcpy(a_register_msg_to_tx->chunk_eid, eid_from_worker_msg);
              a_register_msg_to_tx->io_type = REQUEST_REGISTER;

              // memset(&a_chunk_msg_desc->mbuf, 0, sizeof(struct rte_mbuf));
              a_register_msg_to_tx->chunk_size = 20 + 4 + 1 + 4 + 1;
              register_desc->connect_2_gnr_type = 1;
              register_desc->delayParameter = 500;
              register_desc->isGlobalVisable = 1;
              register_desc->ttl = 1;

              rte_memcpy(a_register_msg_to_tx->chunk, register_desc,
                         sizeof(struct register_desc));
              // printf(i);

              if (rte_ring_enqueue(send_ring_to_tx, a_register_msg_to_tx) < 0)
              {
                WRITE_WARN(
                    "Not enough room in the ring to enqueue on socket:%u \n",
                    rte_socket_id());
                rte_mempool_put(pool, a_register_msg_to_tx);
              }
            }
          }
          else // consider using a special folder to place these strange
               // chunks
          {
            WRITE_WARN("Receive an unknown request with wrong chunk eid!\n");
            // TODO: construct write failed notify
          }
        }
      }
      else if (a_chunk_msg_desc->io_type == REQUEST_IO_READ)
      {
        WRITE_LOG("we receive a read request!\n");
        bucket = get_bucket_from_hex_eid(bucket_num_for_cs_two, a_chunk_msg_desc->chunk_eid);
        table = a_chunk_msg_desc->chunk_size;
        // todo : take tab from msg
        // ret = cs_two_lookup_with_hash_in_write(
        //    pool, send_ring_to_tx, conf->cs_two, conf_worker->cs_two, table,
        //    bucket, a_chunk_msg_desc->chunk_eid, &(a_chunk_msg_desc->mbuf), uint32_t bucket_num_for_cs_two);

        ret = CACHE_HIT_ON_FISK;
        if (ret == CACHE_NO_HIT)
        {
          WRITE_LOG(
              "wrong situation!this request can not hit in the write core!\n");
          rte_mempool_put(pool, a_chunk_msg_desc);
        }
        else if (ret == CACHE_HIT_ON_FISK)
        {
          if (lookup_path(a_chunk_msg_desc->chunk_eid, fs_path_for_eid) == 0)
          {
            // WRITE_LOG("we finish look path!\n");
            // examine whether the chunk file exists
            if (is_file_exist(fs_path_for_eid) < 0)
            {
              // TODO: construct read failed notify
              WRITE_LOG("fail! is_file_exist\n");
            }
            else
            {
              //printf("the size is %016x\n", a_chunk_msg_desc->size);
              if (a_chunk_msg_desc->size > SIZE_OF_ONE_CHUNK) {
                WRITE_WARN("too big! %d\n", a_chunk_msg_desc->size);
                continue;
              }
              long rsize =
                  read_file(chunk_temp, fs_path_for_eid,
                            a_chunk_msg_desc->offset, a_chunk_msg_desc->size);
              if (rsize <= 0)
              {
                WRITE_WARN("fail! %d\n", rsize);
                continue;
              }

              // fp = fopen(fs_path_for_eid, "r");
              // fread(chunk_temp, SIZE_OF_ONE_CHUNK, 1, fp);
              // fclose(fp);
              conf->stats.nb_chunk_read_from_ssd += 1;
              WRITE_LOG("finish reading chunk!\n");
              // TODO: construct read finish notify
              while (1) // if no space for notify, it will be stuck here
              {
                if (rte_mempool_get(pool, (void **)&a_chunk_msg_desc_to_tx) <
                    0)
                {
                  WRITE_WARN(
                      "Not enough entries in the mempool on message packet "
                      "pool on socket:%u \n",
                      rte_socket_id());
                }
                else
                {
                  break;
                }
              }
              //printf("the msg desc to tx is %p", a_chunk_msg_desc_to_tx);
              // construct a chunk_msg_desc_to_tx
              a_chunk_msg_desc_to_tx->io_type = NOTIFY_IO_READ_FINISH;
              a_chunk_msg_desc_to_tx->offset = a_chunk_msg_desc->offset;
              a_chunk_msg_desc_to_tx->size = a_chunk_msg_desc->size;
              a_chunk_msg_desc_to_tx->chunk_size = rsize;
              rte_memcpy(a_chunk_msg_desc_to_tx->chunk_eid,
                         a_chunk_msg_desc->chunk_eid, EID_LEN_HEX + 1);
			        rte_memcpy(a_chunk_msg_desc_to_tx->chunk, chunk_temp,
                         a_chunk_msg_desc->size);
              rte_memcpy(&a_chunk_msg_desc_to_tx->mbuf, &a_chunk_msg_desc->mbuf,
                         sizeof(struct rte_mbuf));

              if (rte_ring_enqueue(send_ring_to_tx, a_chunk_msg_desc_to_tx) <
                  0)
              {
                WRITE_WARN(
                    "Not enough room in the ring to enqueue on socket:%u \n",
                    rte_socket_id());
                rte_mempool_put(pool, a_chunk_msg_desc_to_tx);
              }
              WRITE_LOG(
                  "we put the chunk to the tx core from fisk,and then copy the "
                  "chunk into dram lru queue!\n");
              /*rte_memcpy(
                  conf->cs_two
                      ->dram_queue[conf_worker->cs_two->hash_table[bucket]
                                       .entry[table]
                                       .dram_index]
                      .dram_packet_pool_chunk_addr,
                  chunk_temp, SIZE_OF_ONE_CHUNK);
              conf_worker->cs_two->hash_table[bucket].entry[table].dram_flag =
                  CHUNK_STORE_IN_BOTH;*/
              rte_mempool_put(pool, a_chunk_msg_desc);
            }
          }
          else
          {
            WRITE_WARN("Receive an unknown request with wrong chunk eid!\n");
            rte_mempool_put(pool, a_chunk_msg_desc);
            // TODO: construct read failed notify
          }
        }
        else if (ret == CACHE_HIT_ON_DRAM)
        {
          conf->stats.int_dram_hit += 1;
          rte_mempool_put(pool, a_chunk_msg_desc);
        }
        else if (ret == CHUNK_STORE_IN_BOTH)
        {
          WRITE_LOG("[lcore:%d]we have pushed the chunk to tx core!\n",
                    lcore_id);
          rte_mempool_put(pool, a_chunk_msg_desc);
        }
      }
      else if (a_chunk_msg_desc->io_type == REQUEST_REGISTER)
      {
        //TODO: add register operation
        printf("2\n");
        printf("#########WRITER CORE: recovery register, eid is %s", a_chunk_msg_desc->chunk_eid);

        while (1)
        {
          if (rte_mempool_get(pool, (void **)&a_register_msg_to_tx) < 0)
          {
            WRITE_WARN(
                "Not enough entries in the mempool on message packet "
                "pool on socket:%u \n",
                rte_socket_id());
          }
          else
          {
            break;
          }
        }
        // construct a register msg (send to tx core)
        strcpy(a_register_msg_to_tx->chunk_eid, a_chunk_msg_desc->chunk_eid);
        a_register_msg_to_tx->io_type = REQUEST_REGISTER;

        // memset(&a_chunk_msg_desc->mbuf, 0, sizeof(struct rte_mbuf));
        a_register_msg_to_tx->chunk_size = 20 + 4 + 1 + 4 + 1;
        register_desc->connect_2_gnr_type = 1;
        register_desc->delayParameter = 500;
        register_desc->isGlobalVisable = 1;
        register_desc->ttl = 1;

        rte_memcpy(a_register_msg_to_tx->chunk, register_desc,
                   sizeof(struct register_desc));
        // printf(i);

        if (rte_ring_enqueue(send_ring_to_tx, a_register_msg_to_tx) < 0)
        {
          WRITE_WARN(
              "Not enough room in the ring to enqueue on socket:%u \n",
              rte_socket_id());
          rte_mempool_put(pool, a_register_msg_to_tx);
        }

        rte_mempool_put(pool, a_chunk_msg_desc);
      }
      else
      {
        WRITE_WARN("Receive an unknown request with type:%u \n",
                   a_chunk_msg_desc->io_type);
        rte_mempool_put(pool, a_chunk_msg_desc);
        // consider whether to construct a notify
      }

      // after the chunk_dssc is used,it should be released
      // rte_mempool_put(pool, a_chunk_msg_desc);
    }
  }
  return 0;
}
