#include "seadp_client.h"
#include "list.h"
#include <stdio.h>
#include <sys/time.h>


#include "seadp_receiver.h"
// #include "seadp_sender.h"

#define NUMBER 1024



#define HASH_8BITS 256
#define HASH_16BITS 65536

typedef struct {
    struct list_head list;
    uint8_t Eid[20];
    seadp_info_t * seadp_info;
}map_node_t;

typedef struct{
    struct list_head seadp_info_table[HASH_8BITS];
    uint8_t local_eid[20];
    uint8_t local_ip[20];
    struct rte_mempool *pool;
    uint16_t queue_id;
}seadp_common_t;

static inline uint8_t hash8(uint8_t *buf, int len)
{
	uint8_t result = 0;
    int i = 0;
	for (; i < len; i++)
		result ^= buf[i];

	return result;
}

static inline uint16_t hash16(uint8_t *buf, int len)
{
	uint16_t result = 0;
    int i = 0;
	for (; i < len / 2 * 2; i += 2)
		result ^= *(uint16_t *)(buf + i);

	if (len % 2)
		result ^= (uint8_t)(buf[len-1]);
	
	return result;
}

static int para_cmp(const unsigned char *firstPara,const unsigned char *secondPara,int cmp_length){
    int cmp=0;
    int i;
    for (i = 0; i < cmp_length; i++){
        if(firstPara[i] != secondPara[i]) {
            cmp=1;
            break;
        }
    }
   return cmp;
}


static inline seadp_info_t * seadp_sender_info_create(uint8_t Eid[20],seadp_info_parameter_t *para){
    seadp_info_t *seadp_info=NULL;
    return seadp_info;
}



static seadp_info_t * seadp_info_table_lookup(struct list_head *seadp_info_table ,uint8_t eid[20]){
    uint8_t key =hash8(eid,20);
    map_node_t *pos =NULL;
    list_for_each_entry(pos,&seadp_info_table[key],list){
        if(0==para_cmp(eid,pos->Eid,20)){
            return pos->seadp_info;
        }
    }
    return NULL;
}
static int seadp_info_table_del_node(struct list_head *seadp_info_table ,uint8_t eid[20]){
    uint8_t key =hash8(eid,20);
    map_node_t *pos =NULL , *q=NULL;
    list_for_each_entry_safe(pos,q,&seadp_info_table[key],list){
        if(0==para_cmp(eid,pos->Eid,20)){
            pos->seadp_info->close(pos->seadp_info->info);
            list_delete_entry(&pos->list);
            rte_free(pos);
            return 0;
        }
    }
    return 0;
}

static int seadp_info_table_add_node(struct list_head *seadp_info_table ,uint8_t eid[20],seadp_info_t *seadp_info){
    uint8_t key =hash8(eid,20);
    map_node_t *pos =NULL , *q=NULL;
    list_for_each_entry_safe(pos,q,&seadp_info_table[key],list){
        if(0==para_cmp(eid,pos->Eid,20)){
            return 0; //重复请求一个seadp正在接收的chunk 或重复创建发送的seadp_info
        }
    }
    map_node_t *map_node = (map_node_t*)rte_malloc(NULL,sizeof(map_node_t),0);
    map_node->seadp_info=seadp_info;
    rte_memcpy(map_node->Eid,eid,20);
    list_add_head(&map_node->list,&seadp_info_table[key]);
    return 0;
}

void *seadp_init(uint8_t local_eid[20],uint8_t local_ip[16],struct rte_mempool *pool,uint16_t queue_id){
    SEADP_DBG(RTE_LOG_DEBUG,"seadp init \n");
    seadp_common_t *seadp_common=(seadp_common_t*)rte_malloc(NULL,sizeof(seadp_common_t),0);
    rte_memcpy(seadp_common->local_eid,local_eid,20);
    rte_memcpy(seadp_common->local_ip,local_ip,16);
    seadp_common->pool=pool;
    seadp_common->queue_id=queue_id;
    int i=0;
    for(i=0;i<HASH_8BITS;i++){
        init_list_head(&seadp_common->seadp_info_table[i]);
    }
    return (void*)seadp_common;
}
int seadp_create_task(void *seadp_ptr,uint8_t eid[20],uint8_t ip[16] ,call_back cb,void *cb_ptr ){
    
    seadp_common_t *seadp_common = (seadp_common_t*)seadp_ptr;
    seadp_info_t *seadp_info=receiver_seadp_info_create(seadp_common->local_eid,seadp_common->local_ip,eid,ip,cb,cb_ptr,NULL,seadp_common->pool,seadp_common->queue_id);
    if(seadp_info!=NULL){
        seadp_info_table_add_node(seadp_common->seadp_info_table,eid,seadp_info);//散列表增加dstEid ,seadp_info的映射
        return 0;
    }
    return -1;
}
void seadp_process_packets(void *seadp_ptr,struct rte_mbuf *mbuf){
    seadp_common_t *seadp_common = (seadp_common_t*)seadp_ptr;
    seadp_info_t *seadp_info=NULL;
    // struct list_head *seadp_info_table = ((seadp_common_t*)seadp_ptr)->seadp_info_table;
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ipv6_hdr_t *ipv6_hdr = ( ipv6_hdr_t *)RTE_PTR_ADD(eth_hdr, sizeof( struct ether_hdr));
    id_hdr_t *id_hdr = ( id_hdr_t *)RTE_PTR_ADD(ipv6_hdr, sizeof( ipv6_hdr_t));
    seadp_hdr_t *seadp_hdr = ( seadp_hdr_t *)RTE_PTR_ADD(id_hdr, sizeof( id_hdr_t));
    switch(seadp_hdr->pflag){
        case CFIN:
        case CREQ:
        case REQ:   seadp_info=seadp_info_table_lookup(seadp_common->seadp_info_table,id_hdr->dstEid);  
                    if(seadp_info==NULL){
                        seadp_info=seadp_sender_info_create(id_hdr->dstEid,NULL);
                        if(seadp_info!=NULL){
                            seadp_info_table_add_node(seadp_common->seadp_info_table,id_hdr->dstEid,seadp_info);
                        }
                    }
                    seadp_info->process_packets(seadp_info->info,mbuf); 
                    break;
        case CDAT:
        case DAT:   seadp_info=seadp_info_table_lookup(seadp_common->seadp_info_table,id_hdr->srcEid);
                    if(seadp_info!=NULL){
                        seadp_info->process_packets(seadp_info->info,mbuf); 
                    }
                    break;             
        default: break;
    }
}
void seadp_heartbeat(void *seadp_ptr){
    struct list_head *seadp_info_table = ((seadp_common_t*)seadp_ptr)->seadp_info_table;
    int i=0;
    for(i=0;i<HASH_8BITS;i++){
        map_node_t *pos =NULL , *q=NULL;
        list_for_each_entry_safe(pos,q,&seadp_info_table[i],list){
            if(pos->seadp_info->heartbeat(pos->seadp_info->info)<0){
                pos->seadp_info->close(pos->seadp_info->info);
                list_delete_entry(&pos->list);
                rte_free(pos);
            }
        }
    }
}

int seadp_cancel_task(void *seadp_ptr,uint8_t eid[20]){
    seadp_common_t *seadp_common = (seadp_common_t*)seadp_ptr;
    
    return seadp_info_table_del_node(seadp_common->seadp_info_table,eid);
}

int seadp_get_task_status(void *seadp_ptr,uint8_t eid[20]){
    seadp_common_t *seadp_common = (seadp_common_t*)seadp_ptr;
    seadp_info_t *seadp_info=seadp_info_table_lookup(seadp_common->seadp_info_table,eid);  
    if(seadp_info==NULL){
        return -2;
    }
    return seadp_info->get_status(seadp_info->info);
}
int seadp_set_option(void *seadp_ptr, int type,uint8_t *buf ,int len){

    return 0;
}


uint64_t get_time_ms(){
    struct timeval time;
    gettimeofday(&time,NULL);
    return(uint64_t)time.tv_sec*1000+time.tv_usec/1000;//ms
}


static unsigned short seanet_checksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size)
    {
        cksum += *(unsigned char*)buffer;
    }
    cksum = (cksum>>16) + (cksum&0xffff);
    cksum += (cksum>>16);
    return (unsigned short)(~cksum);
    //if size if odd,auto fill 0x00
}
//fill seadp checksum
int get_seadp_checksum(seadp_hdr_t *seadp_header,unsigned char *payload_buff,size_t payload_len){
    unsigned short seadp_checksum=0;
    unsigned char *buffer = (unsigned char*)rte_malloc(NULL,seadp_header->hdrlen+payload_len,0);
    if( buffer == NULL )
    {
      SEADP_DBG( DBG_LEVEL_ERROR, "Error - unable to allocate checksum memory\n");
      return -1;
    }
    rte_memcpy(buffer,seadp_header,seadp_header->hdrlen);
    if(payload_len>0){
        rte_memcpy(buffer+seadp_header->hdrlen,payload_buff,payload_len);
    }
    seadp_hdr_t * sh = (seadp_hdr_t *)buffer;
    sh->cflag = (unsigned char)0;
    sh->sflag = (unsigned char)0;

    seadp_checksum = seanet_checksum((unsigned short *)buffer, seadp_header->hdrlen+payload_len);
    rte_free(buffer);
    buffer=NULL;
    return (int)seadp_checksum;
}


