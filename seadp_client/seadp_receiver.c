#include "seadp_receiver.h"
#include "malloc_chunk_buf.h"
#include <sys/uio.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <arpa/inet.h>

// #define USECC
#ifdef USECC
#include "bbr_congestion_control/seadp_receiver_cc.h"
#endif

static void receiver_process_packets(void * void_info,struct rte_mbuf *mbuf);

static int receiver_heartbeat(void * void_info);
static void receiver_close(void * void_info);
static int seadp_rpt_output(seadp_receiver_info_t * info, unsigned int p_num);
static int send_fin(seadp_receiver_info_t * info);
static int calculate_timeout(seadp_receiver_info_t * info);
static int delete_req_packet(seadp_receiver_info_t * info , int  rpt_number);
static int send_first_req(seadp_receiver_info_t * info, int flags);
static int seadp_req(seadp_receiver_info_t * info, int flags);

static int receiver_get_status(void * void_info){
    seadp_receiver_info_t *info = (seadp_receiver_info_t*)void_info;
    if(0==info->chunksize){
        return 0;
    }
    return info->recv_data_size/info->chunksize*100;
}

seadp_info_t * receiver_seadp_info_create(uint8_t local_eid[20],uint8_t local_ip[16],uint8_t chunk_eid[20],uint8_t dst_ip[16],  \
                call_back cb,void *cb_ptr,seadp_info_parameter_t *para,struct rte_mempool *pool ,uint16_t queue_id){
    seadp_info_t *seadp_info=(seadp_info_t*)rte_malloc(NULL,sizeof(seadp_info_t),0);
    seadp_receiver_info_t * info =(seadp_receiver_info_t*)rte_malloc(NULL,sizeof(seadp_receiver_info_t),0);
    seadp_info->info=info;

    //TODO 绑定函数指针
    seadp_info->process_packets=receiver_process_packets;
    seadp_info->heartbeat=receiver_heartbeat;
    seadp_info->close=receiver_close;
    seadp_info->get_status=receiver_get_status;
    info->chunksize = 0;
    info->recv_data_size=0;
    info->buff=NULL;
    info->abandon_packet_number = 0;
    info->Port = htons(DEFAULT_PORT);
    info->req_info = (req_info_t*)rte_malloc(NULL,sizeof(req_info_t),0);
    info->RTO_PT = INIT_RTO;
    info->last_recv_packet_time = 0;
    info->packet_number = 1;
    req_info_t *  req_info = info->req_info;
    req_info->MTU = DEFAULT_MTU;
    req_info->send_max_pnum = 0;
    //req_info->recv_continue_pnum = NULL;
    // req_info->recv_max_num = NULL;
    bzero(req_info->req_packet,MAX_PACKET_NUMBER*sizeof(req_info_t *)); //有无必要？
    init_list_head(&req_info->pre_req_list_head);
    if(dst_ip!=NULL){
        rte_memcpy(info->d_ip,dst_ip,16);
    }else{
        //TODO 从解析获取目的IP
    }
    if(para !=NULL){
        info->sf = para->sf;
        info->cf = para->cf;
        info->Port = para->dstport!=0 ? para->dstport : DEFAULT_RECV_PORT ;
    }else{
        info->sf=0;
        info->cf=0;
        info->Port=DEFAULT_RECV_PORT;
    }
    rte_memcpy(info->local_eid,local_eid,20);
    rte_memcpy(info->l_ip,local_ip,16);
    rte_memcpy(info->Eid,chunk_eid,20);
    info->cb=cb;
    info->cb_ptr = cb_ptr;
    info->stat = 1;
    info->pool = pool;
    info->queue_id=queue_id;

    send_first_req(info,0);
    info->send_first_req_count=1;
    #ifdef USECC
    // BBR INIT
    seadp_cc_t*  cc = seadp_cc_create(sock,seadp_rpt_output,300000*8*1000,  100*8*1000, 300*8*1000);
    if(cc != NULL){
        info->cc = cc;
    }
    #endif

    return seadp_info;
}

static int seadp_output(seadp_receiver_info_t *info,struct iovec iov[2]){

    SEADP_DBG(DBG_LEVEL_TRACE,"start !\n");
    //malloc mbuf
    struct rte_mbuf * m[1] ;
    m[0]= rte_pktmbuf_alloc(info->pool);
    
    //ethernet layer
    struct ether_hdr * eth_hdr = rte_pktmbuf_mtod(m[0], struct ether_hdr *);
    eth_hdr->ether_type = htons(ETHER_TYPE_IPv6);

    //ip layer
    ipv6_hdr_t *ip_header = (ipv6_hdr_t *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
    ip_header->version = 6;
    ip_header->trafficClass=0;
    bzero(ip_header->flowLable,3);
    ip_header->payloadLength = ntohs(iov[0].iov_len+iov[1].iov_len+ID_HDR_LEN);
    ip_header->protocol = PROTO_SEANET;
    ip_header->hopLimit = 0xff;
    rte_memcpy(&ip_header->dstAddr, info->d_ip, 16);
    rte_memcpy(&ip_header->srcAddr, info->l_ip, 16);

    //id layer
    id_hdr_t *id_header = (id_hdr_t *)RTE_PTR_ADD(ip_header, sizeof(ipv6_hdr_t));
    id_header->next = PROTO_SEADP;
    id_header->len = 44;
    id_header->attr = htons(0x0009);
    rte_memcpy(&id_header->dstEid, info->Eid, 20);
    rte_memcpy(&id_header->srcEid, info->local_eid, 20);
   
    //seadp layer
    seadp_hdr_t *seadp_hdr = (seadp_hdr_t *)RTE_PTR_ADD(id_header, sizeof(id_hdr_t));
    rte_memcpy(&seadp_hdr, iov[1].iov_base,iov[1].iov_len);
    
    //data layer
    if(iov[0].iov_len!=0){
        char * data = (char *) RTE_PTR_ADD (seadp_hdr,iov[0].iov_len);
        rte_memcpy(&data, iov[0].iov_base,iov[0].iov_len);
    }
    //send m
    int s =rte_eth_tx_burst(0, info->queue_id, m, 1);
    SEADP_DBG(DBG_LEVEL_TRACE,"end %d!\n",s);
    return s;
    
}



static void receiver_close(void * void_info){
    seadp_receiver_info_t *info = (seadp_receiver_info_t*)void_info;
    send_fin(info);
    req_info_t *  req_info = info->req_info;
    int i=info->abandon_packet_number;
    for(; i<info->packet_number;i++){
        if(req_info->req_packet[i]!=NULL){
            delete_req_packet(info,i);
        }
    }
    rte_free(req_info);
    req_info = NULL;
    if(info->buff!=NULL){
        free_chunk_buf(info->cb_ptr ,info->buff ,info->chunksize);
	}
    #ifdef USECC
    seadp_cc_destroy(info->cc);
    #endif
    info->stat = 0;
    rte_free(info);
    info=NULL;
    // SEADP_DBG( DBG_LEVEL_TRACE,"recv close!!\n");
}

static int receiver_heartbeat(void * void_info){
    seadp_receiver_info_t *info = (seadp_receiver_info_t*)void_info;
    uint64_t now_time=rte_get_tsc_cycles()/1000000LL;
    if(info->last_recv_packet_time!=0 && now_time - info->last_recv_packet_time > 35000){
        SEADP_DBG( DBG_LEVEL_ERROR,"recv data timeout !\n");
        if(info->send_first_req_count >2){
            return -1;
        }
        info->send_first_req_count++;
        info->last_recv_packet_time=rte_get_tsc_cycles()/1000000LL;
        send_first_req(info,0);
        info->RTO_PT=INIT_RTO;
        SEADP_DBG( DBG_LEVEL_ERROR,"-------------------------------req send  %d !\n",info->send_first_req_count);
    }
    #ifdef USECC
    seadp_cc_heartbeat(info->cc,rte_get_tsc_cycles()/1000000LL);
    #endif
    calculate_timeout(info);
    if(seadp_req(info,0)<0){
        return -1;
    }
    if(info->chunksize == info->recv_data_size && info->chunksize != 0){
        // if(nbytes<info->chunksize){
        //     SEADP_DBG( DBG_LEVEL_TRACE,"buff size too small !!!\n");
        //     return -1;
        // }
        //TODO 将接收好的chunk放到某个地方
        info->cb(info->cb_ptr,info->Eid,info->buff,info->chunksize); 
        info->stat =3;
        return -1;
    }
    return 0;
} 

static inline void add_recv_data_size(seadp_receiver_info_t * info,unsigned long len){
    info->recv_data_size += len;
}

static int send_fin(seadp_receiver_info_t * info){
    seadp_hdr_t* seadp_header = (seadp_hdr_t *)rte_malloc(NULL,sizeof(seadp_hdr_t),0);
    seadp_header->srcPort = info->local_port;
    seadp_header->dstPort = info->Port;
    // seadp_header->version=SEDNET_VERSION;
    seadp_header->pflag=CFIN;//REQ=1
    seadp_header->cflag=0;//tentetive
    seadp_header->sflag=0;//tentetive
    seadp_header->hdrlen=sizeof(seadp_hdr_t);
    seadp_header->checksum = 0;
    seadp_header->packetnumber=0;
    seadp_header->off = 0;
    seadp_header->len = 0;
    seadp_header->checksum = (uint32_t)get_seadp_checksum(seadp_header,NULL,0);
    SEADP_DBG( DBG_LEVEL_TRACE,"ton checksum %d\n",seadp_header->checksum);
    SEADP_DBG( DBG_LEVEL_TRACE,"toh checksum %d\n",ntohs(seadp_header->checksum));
    struct iovec iov[2];
    iov[1].iov_base=NULL;
    iov[1].iov_len=0;
    iov[0].iov_base=seadp_header;
    iov[0].iov_len=seadp_header->hdrlen;
    int len = seadp_output(info,iov);
    if( len > 0){
        SEADP_DBG( DBG_LEVEL_TRACE,"send fin packet,send time : %llu\n",rte_get_tsc_cycles());
        return 0;
    }else{
        return -1;
    }
    return 0;
}

static int recv_first_packet(seadp_receiver_info_t * info, unsigned long int chunksize,unsigned long right_off){
    if(chunksize>0){
        info->chunksize = chunksize;
        pre_req_node_t * temp = (pre_req_node_t *)rte_malloc(NULL,sizeof(pre_req_node_t),0);
        temp->right_off = chunksize-1;
        temp->left_off = right_off+1;
        add_recv_data_size(info,right_off+1);
        SEADP_DBG( DBG_LEVEL_TRACE,"first off: %u\n",temp->left_off);
        list_add_tail(&temp->list,&info->req_info->pre_req_list_head);
        info->req_info->send_max_pnum=1;
        //info->req_info->recv_continue_pnum=1;
        // info->req_info->recv_max_num = 1;
        info->max_off = right_off;
        // info->pre_req_max_off = right_off;
        info->packet_number=2;
        rte_free(info->req_info->req_packet[1]);
        info->req_info->req_packet[1]=NULL;
        SEADP_DBG( DBG_LEVEL_TRACE,"recv first segment!!\n");
        return 0;
    }
    return -1;
}

// buff 必须有足够长度（optlen+2）放tlv
static int set_tlv_header(tlv_optname_t optname, void *buff,const void *optval, const int optlen){
    unsigned char * tlv_buff = (unsigned char *)buff;
    switch(optname){
        case TLV_SREQ : *tlv_buff = 1;break;
        case TLV_TIMESTAMP : *tlv_buff = 2;break;
        case TLV_MTU : *tlv_buff = 3;break;
        case TLV_NOP : *tlv_buff = 0;bzero(buff,(size_t)optlen);return optlen;break;
        default :
            return -1;
    }
    *(tlv_buff+1)=optlen+2;
    rte_memcpy(tlv_buff+2,optval,(size_t)optlen);
    return optlen+2;
}

static int calculate_timeout(seadp_receiver_info_t * info){
    if(info->packet_number==1){
        return 0;
    }
    unsigned short i = info->abandon_packet_number+1;
    for (; i <= info->req_info->send_max_pnum&&i<MAX_PACKET_NUMBER; ++i)
    {
        req_packet_t * req_packet = info->req_info->req_packet[i];
        if(req_packet==NULL){continue;}
        uint64_t now_time = rte_get_tsc_cycles()/1000000LL;

        //if((now_time - req_packet->send_time<=info->RTO_PT)||(req_packet->stat == 4 && ((now_time - req_packet->send_time)*1.2*cc_get_bw(info->cc)/1000>req_packet->req_data_size))){
        if( req_packet->stat==2 && now_time - req_packet->send_time > info->RTO_PT*1.2){

            SEADP_DBG( DBG_LEVEL_TRACE,"req timeout, packet_number : %u \n",i);
            pre_req_node_t * temp=NULL;
            temp = (pre_req_node_t*)rte_malloc(NULL,sizeof(pre_req_node_t),0);
            temp->left_off = req_packet->off;
            SEADP_DBG( DBG_LEVEL_TRACE,"req timeout, off : %llu\n",req_packet->off);
            SEADP_DBG( DBG_LEVEL_TRACE,"req timeout, len : %llu\n",req_packet->len);
            temp->right_off = req_packet->off + req_packet->len - 1;
            list_add_head(&temp->list,&info->req_info->pre_req_list_head);
            // add_recv_data_size(info,have_recv_data);
            delete_req_packet(info,i);
            #ifdef USECC
            seadp_cc_remove_req_packet(info->cc,i);//inform cc
            #endif
            info->req_info->req_packet[i]=NULL;
            req_packet=NULL;
        }else if(req_packet->stat == 4 && now_time - req_packet->send_time > info->RTO_PT*1.4){
            unsigned long have_recv_data=req_packet->len;

            // info->RTO_PT = info->RTO_PT+1;
            SEADP_DBG( DBG_LEVEL_TRACE,"recv data timeout, packet_number : %u \n",i);
            SEADP_DBG( DBG_LEVEL_TRACE,"recv data timeout, off : %llu\n",req_packet->off);
            SEADP_DBG( DBG_LEVEL_TRACE,"recv data timeout, len : %llu\n",req_packet->len);

            recv_data_node_t * recv_data_node=NULL,*q=NULL;
            pre_req_node_t * temp = NULL;
            unsigned long last_node_last_off = req_packet->off-1;
            list_for_each_entry_safe(recv_data_node, q, &req_packet->recv_data_list, list){
                    if(recv_data_node->off > last_node_last_off+1){
                        temp = (pre_req_node_t*)rte_malloc(NULL,sizeof(pre_req_node_t),0);
                        temp->left_off = last_node_last_off+1;
                        temp->right_off = recv_data_node->off-1;
                        have_recv_data = have_recv_data-(temp->right_off+1-temp->left_off);
                        list_add_head(&temp->list,&info->req_info->pre_req_list_head);
                    }
                    last_node_last_off = recv_data_node->off+recv_data_node->len-1;
            }
            if(last_node_last_off < req_packet->off+req_packet->len-1){
                temp = (pre_req_node_t*)rte_malloc(NULL,sizeof(pre_req_node_t),0);
                temp->left_off = last_node_last_off+1;
                temp->right_off = req_packet->off+req_packet->len-1;
                have_recv_data = have_recv_data - (temp->right_off+1-temp->left_off);
                list_add_head(&temp->list,&info->req_info->pre_req_list_head);

            }
            #ifdef USECC
            seadp_cc_remove_req_packet(info->cc,i);//inform cc
            #endif
            if(have_recv_data>0){

                add_recv_data_size(info,have_recv_data);
            }
            delete_req_packet(info,i);
            info->req_info->req_packet[i]=NULL;
            req_packet=NULL;
        }else{
            SEADP_DBG( DBG_LEVEL_TRACE,"now_time : %llu\n",now_time);
            SEADP_DBG( DBG_LEVEL_TRACE,"req_packet->send_time: %llu\n",req_packet->send_time);
            SEADP_DBG( DBG_LEVEL_TRACE,"%llu\n",now_time - req_packet->send_time);
            SEADP_DBG( DBG_LEVEL_TRACE,"RTO_PT：%d\n",info->RTO_PT);
            continue;
        }
    }
    // SEADP_DBG( DBG_LEVEL_TRACE,"calculate_timeout over!!!\n");
    return 0;
}

static int inform_recv_packet(seadp_receiver_info_t * info, recv_packet_t * rpt,int len){
    int i = 0;
    for(;i<len;i++){
        if(info->req_info->req_packet[rpt[i].packet_num]==NULL){
            continue;
        }
        SEADP_DBG( DBG_LEVEL_TRACE,"recv data packet_number : %u\tleft_off : %u\tright_off : %u\n",rpt[i].packet_num,rpt[i].left_off,rpt[i].right_off);
        // if(rpt[i].packet_num>info->req_info->recv_max_num){info->req_info->recv_max_num = rpt[i].packet_num;}
        //if(rpt[i].packet_num==info->req_info->recv_continue_pnum+1){info->req_info->recv_continue_pnum++ ;}
        req_packet_t * req_packet = info->req_info->req_packet[rpt[i].packet_num];
        info->last_recv_packet_time = rte_get_tsc_cycles()/1000000LL;
        if(req_packet->off>rpt[i].left_off||req_packet->off+req_packet->len-1<rpt[i].right_off){
            printf("packet error!!!\n");
            continue;
        }
        // list NULL
        if(list_empty(&req_packet->recv_data_list)){
            req_packet->stat = 4;
            recv_data_node_t * temp = (recv_data_node_t *)rte_malloc(NULL,sizeof(recv_data_node_t),0);
            temp->off = rpt[i].left_off;
            temp->len = rpt[i].right_off - rpt[i].left_off + 1;
            list_add_head(&temp->list,&req_packet->recv_data_list);
            SEADP_DBG( DBG_LEVEL_TRACE,"add change recv off %u  len %d\n",temp->off,temp->len);
        }else{
            recv_data_node_t * recv_data_node=NULL,*q=NULL;
            unsigned long last_node_right_off = 0;
            int finish =0;
            list_for_each_entry_safe(recv_data_node, q, &req_packet->recv_data_list, list){

                if(recv_data_node->off>rpt[i].left_off&&rpt[i].left_off>last_node_right_off){
                    finish++;
                    if(rpt[i].left_off==last_node_right_off+1&&rpt[i].right_off+1==recv_data_node->off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 1 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        (list_entry(recv_data_node->list.prev,recv_data_node_t ,list))->len += rpt[i].right_off+1-rpt[i].left_off+recv_data_node->len;
                        list_delete_entry(&recv_data_node->list);
                        rte_free(recv_data_node);
                        break;
                    }else if(rpt[i].left_off==last_node_right_off+1 && rpt[i].right_off+1<recv_data_node->off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 2 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        (list_entry(recv_data_node->list.prev,recv_data_node_t ,list))->len += rpt[i].right_off+1-rpt[i].left_off;
                        break;
                    }else if(rpt[i].right_off+1==recv_data_node->off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 3 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        recv_data_node->off = rpt[i].left_off;
                        recv_data_node->len += rpt[i].right_off+1-rpt[i].left_off;
                        break;
                    }else if(rpt[i].left_off>last_node_right_off+1 && rpt[i].right_off+1<recv_data_node->off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 4 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        recv_data_node_t * temp = (recv_data_node_t *)rte_malloc(NULL,sizeof(recv_data_node_t),0);
                        temp->off = rpt[i].left_off;
                        temp->len = rpt[i].right_off - rpt[i].left_off + 1;
                        list_insert(&temp->list,recv_data_node->list.prev,&recv_data_node->list);
                        break;
                    }else{
                        finish = 0;
                    }
                }
                if(recv_data_node->list.next ==  &req_packet->recv_data_list){
                    if(recv_data_node->off+recv_data_node->len == rpt[i].left_off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 5 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        recv_data_node->len += rpt[i].right_off+1-rpt[i].left_off;
                        finish++;
                        break;
                    }else if (recv_data_node->off+recv_data_node->len < rpt[i].left_off){
                        SEADP_DBG( DBG_LEVEL_TRACE,"add change 6 recv r l off %u  %u\n",rpt[i].right_off,rpt[i].left_off);
                        recv_data_node_t * temp = (recv_data_node_t *)rte_malloc(NULL,sizeof(recv_data_node_t),0);
                        temp->off = rpt[i].left_off;
                        temp->len = rpt[i].right_off - rpt[i].left_off + 1;
                        list_add_tail(&temp->list, &req_packet->recv_data_list);
                        finish++;
                        break;
                    }
                }
                last_node_right_off = recv_data_node->off+recv_data_node->len-1;
            }
            if(finish == 0){
                SEADP_DBG( DBG_LEVEL_TRACE,"insert error , recv error packet !\n");
            }
        }


        unsigned long have_recv_size = 0;
        // if(!list_empty(&req_packet->recv_data_list)){
        if((list_entry(req_packet->recv_data_list.next,recv_data_node_t,list))->off == req_packet->off && (list_entry(req_packet->recv_data_list.next,recv_data_node_t,list))->len == req_packet->len){
            have_recv_size = req_packet->len;
            req_packet->len = 0;
        }
        // }
        if(have_recv_size != 0){
            add_recv_data_size(info,have_recv_size);
            delete_req_packet(info,rpt[i].packet_num);
            req_packet = NULL;
        }
    }
    int j = info->abandon_packet_number+1;
    for(; j < info->req_info->send_max_pnum; j++){
        if(NULL == info->req_info->req_packet[j] && NULL == info->req_info->req_packet[j-1] ){
            info->abandon_packet_number = j;
        }else{
            break;
        }
    }
    return 0;

}


static int seadp_rpt_output(seadp_receiver_info_t * info, unsigned int p_num){
    if(p_num> MAX_PACKET_NUMBER){ return -1;}
    int len=-1;
    struct iovec iov[2];
    iov[1].iov_base=NULL;
    iov[1].iov_len=0;
    req_info_t * req_info = info->req_info;
    if(req_info->req_packet[p_num]==NULL){  SEADP_DBG( DBG_LEVEL_TRACE,"packet info NULL\n");
        return -2;
    }
    iov[0].iov_base = req_info->req_packet[p_num]->buff;
    iov[0].iov_len = req_info->req_packet[p_num]->seadp_header_len;
    len = seadp_output(info,iov);
    if( len > 0){
        if(info->req_info->send_max_pnum < p_num){
            info->req_info->send_max_pnum = p_num;
        }

        SEADP_DBG( DBG_LEVEL_TRACE,"send req packet_number : %u\n",p_num);
        req_info->req_packet[p_num]->send_time = rte_get_tsc_cycles()/1000000LL;
        req_info->req_packet[p_num]->stat = 2;
        // info->last_send_req_time=req_info->req_packet[p_num]->send_time;
        //TODO 更新 已发送最大偏移
        if(info->max_off < req_info->req_packet[p_num]->off+req_info->req_packet[p_num]->len-1){
            info->max_off = req_info->req_packet[p_num]->off+req_info->req_packet[p_num]->len-1;
        }
        return 0;
    }else{
        SEADP_DBG( DBG_LEVEL_TRACE,"send failed!!! len : %u \n",len);
        return -1;
    }
    return -2;
}

static int delete_req_packet(seadp_receiver_info_t * info , int  rpt_number){
    req_info_t * req_info = info->req_info;

    if(req_info->req_packet[rpt_number]->buff!=NULL){

        rte_free(req_info->req_packet[rpt_number]->buff);
    }

    if(req_info->req_packet[rpt_number]!=NULL){

        if(!list_empty(&req_info->req_packet[rpt_number]->sreq_head_list)){
            sreq_t * p=NULL, *sreq=NULL;
            list_for_each_entry_safe(sreq, p, &req_info->req_packet[rpt_number]->sreq_head_list, list){
                list_delete_entry(&sreq->list);
                rte_free(sreq);
            }
        }
        if(!list_empty(&req_info->req_packet[rpt_number]->recv_data_list)){
            sreq_t * recv_data=NULL, *q = NULL;
            list_for_each_entry_safe(recv_data, q, &req_info->req_packet[rpt_number]->recv_data_list, list){
                list_delete_entry(&recv_data->list);
                rte_free(recv_data);
            }
        }
        rte_free(req_info->req_packet[rpt_number]);
        req_info->req_packet[rpt_number]=NULL;
    }
    SEADP_DBG( DBG_LEVEL_TRACE,"delete_req_packet num %d\n",rpt_number);
    return 0;
}


// static int req_times = 0; //temp
static int send_first_req(seadp_receiver_info_t * info, int flags){

    if(info->req_info->req_packet[1]!= NULL){
        // SEADP_DBG( DBG_LEVEL_TRACE,"now : %lld\n",rte_get_tsc_cycles()/1000000LL);
        if(rte_get_tsc_cycles()/1000000LL-info->req_info->req_packet[1]->send_time<3*INIT_RTO){
            return 0;
        }
        SEADP_DBG( DBG_LEVEL_TRACE,"first req timeout!!!\n");
        info->req_info->req_packet[1]->sreq_num++;

    }else{
            info->req_info->req_packet[1]=(req_packet_t *)rte_malloc(NULL,sizeof(req_packet_t),0);
            info->req_info->req_packet[1]->sreq_num = 1;
    }
    if(info->req_info->req_packet[1]->sreq_num>5){
        return -1;
    }

    info->req_info->req_packet[1]->seadp_header_len =sizeof(seadp_hdr_t)+4 ; // 添加MTU
    size_t nop=0;
    if(info->req_info->req_packet[1]->seadp_header_len%4 != 0){
        nop = (size_t)(4-info->req_info->req_packet[1]->seadp_header_len%4);

    }
    info->req_info->req_packet[1]->seadp_header_len += nop;


    seadp_hdr_t * seadp_header = (seadp_hdr_t *)rte_malloc(NULL,info->req_info->req_packet[1]->seadp_header_len,0);
    if(seadp_header<=0){
        SEADP_DBG(DBG_LEVEL_ERROR,"malloc error !\n");
    }
    seadp_header->srcPort = info->local_port;
    seadp_header->dstPort = ntohs(DEFAULT_PORT);
    // seadp_header->version=SEDNET_VERSION;
    // TODO
    seadp_header->pflag=CREQ;//REQ=1
    seadp_header->cflag=info->cf;//tentetive
    seadp_header->sflag=info->sf;//tentetive
    seadp_header->hdrlen=info->req_info->req_packet[1]->seadp_header_len;
    seadp_header->checksum = 0;
    seadp_header->packetnumber=htons(1);
    seadp_header->off = 0;
    seadp_header->len = 0;
    int pk_mtu = htons(info->req_info->MTU);
    int mtu_len = set_tlv_header(TLV_MTU, ((unsigned char *)seadp_header)+sizeof(seadp_hdr_t),&pk_mtu, 2);
    if(nop>0){
        bzero(((unsigned char *)seadp_header)+4,nop);
    }
    int checksum = get_seadp_checksum(seadp_header,NULL,0);
    seadp_header->checksum = (uint32_t)checksum;
    SEADP_DBG( DBG_LEVEL_TRACE," checksum %u\n",checksum);
    SEADP_DBG( DBG_LEVEL_TRACE,"ton checksum %u\n",seadp_header->checksum);
    SEADP_DBG( DBG_LEVEL_TRACE,"toh checksum %u\n",ntohs(seadp_header->checksum));
    struct iovec iov[2];
    iov[1].iov_base=NULL;
    iov[1].iov_len=0;
    iov[0].iov_base=seadp_header;
    iov[0].iov_len=info->req_info->req_packet[1]->seadp_header_len;
    int len = seadp_output(info,iov);
    if( len > 0){
        SEADP_DBG( DBG_LEVEL_TRACE,"send first req,send time : %llu\n",rte_get_tsc_cycles());
        info->req_info->req_packet[1]->send_time = rte_get_tsc_cycles()/1000000LL;
        info->req_info->req_packet[1]->stat = 2;
        return 0;
    }else{
        return -1;
    }
    return 0;

}


//client send req
static int seadp_req(seadp_receiver_info_t * info, int flags){
    if(info->packet_number==1){

        if( send_first_req(info,flags)>=0){
            return 0;
        }else{
            return -1;
        }

    }else if (info->packet_number>1&&info->packet_number<MAX_PACKET_NUMBER){
        if(list_empty(&info->req_info->pre_req_list_head)){
            return 0;
        }
        #ifdef USECC
        int cwnd = seadp_cc_get_cwnd((seadp_cc_t*)info->cc);
        SEADP_DBG( DBG_LEVEL_TRACE,"seadp cc %d\n",cwnd);
        if(cwnd <100){ return 0;}
        uint32_t pkt_cwnd = cwnd;
        #else
        uint32_t pkt_cwnd = 10000;
        #endif
        uint32_t req_data_len = 0;
        for(; pkt_cwnd>200; pkt_cwnd = pkt_cwnd - req_data_len){
             if(list_empty(&info->req_info->pre_req_list_head)){
                return 0;
            }
            req_packet_t * req_packet = (req_packet_t *)rte_malloc(NULL,sizeof(req_packet_t),0);
            if(req_packet == NULL){
                SEADP_DBG( DBG_LEVEL_TRACE,"malloc error!!!\n");
            }
            info->req_info->req_packet[info->packet_number]= req_packet;
            init_list_head(&req_packet->sreq_head_list);
            init_list_head(&req_packet->recv_data_list);
            req_packet->off = 0;
            req_packet->len = 0;
            req_packet->seadp_header_len = sizeof(seadp_hdr_t);
            req_packet->buff = NULL;
            req_packet->stat = 0;
            // req_packet->sreq_num = 0;
            req_packet->packet_number = htons(info->packet_number);

            // int sreqpkt_cwnd=0;
            SEADP_DBG( DBG_LEVEL_TRACE,"now packet_number %u\n",info->packet_number);

            pre_req_node_t *q=NULL, *pre_req_node=NULL;
            // if(info->pre_req_max_off == info->chunksize){
            //     sreqpkt_cwnd = pkt_cwnd;
            // }else{
            //     sreqpkt_cwnd = pkt_cwnd* SREQ_RATIO;
            // } 248
            list_for_each_entry_safe(pre_req_node, q, &info->req_info->pre_req_list_head, list){
                // if(pkt_cwnd<=500){break;} // 避免把数据切碎
                if(pre_req_node->right_off+1 != info->chunksize){
                    SEADP_DBG( DBG_LEVEL_TRACE,"data rreq num %u\n",info->packet_number);
                }
                // if(req_packet->len==0){
                req_packet->off=pre_req_node->left_off;
                SEADP_DBG( DBG_LEVEL_TRACE,"left_off : %u\n",req_packet->off);
                if(pre_req_node->right_off - pre_req_node->left_off+1 > pkt_cwnd){
                    req_packet->len = pkt_cwnd;
                    pre_req_node->left_off = pre_req_node->left_off + pkt_cwnd ;
                }else{
                    req_packet->len = pre_req_node->right_off- pre_req_node->left_off+ 1;
                    req_packet->off = pre_req_node->left_off;
                    list_delete_entry(&pre_req_node->list);
                    rte_free(pre_req_node);
                }
                break;
            }
            SEADP_DBG( DBG_LEVEL_TRACE,"len : %u\n",req_packet->len);

            if(req_packet->len == 0 ){
                delete_req_packet(info,info->packet_number);
                return 0;
            }

            req_data_len = req_packet->len;


            req_packet->req_data_size = req_packet->len;
            req_packet->seadp_header_len += 4 ; // 添加MTU

            int nop=0;
            if(req_packet->seadp_header_len%4 != 0){
                nop = 4-req_packet->seadp_header_len%4;
            }
            SEADP_DBG( DBG_LEVEL_TRACE,"nop %u\n",nop);
            req_packet->seadp_header_len += nop;
            seadp_hdr_t * seadp_header = (seadp_hdr_t *)rte_malloc(NULL,req_packet->seadp_header_len,0);
            seadp_header->srcPort = info->local_port;
            seadp_header->dstPort = info->Port;
            // seadp_header->version=SEDNET_VERSION;
            // TODO
            seadp_header->pflag=REQ;//REQ=1
            seadp_header->cflag=info->cf;//tentetive
            seadp_header->sflag=info->sf;//tentetive
            seadp_header->hdrlen=req_packet->seadp_header_len;
            seadp_header->checksum = 0;
            seadp_header->packetnumber=req_packet->packet_number;
            seadp_header->off = htonl(req_packet->off);
            seadp_header->len = htonl(req_packet->len);

            unsigned char * tlv_buff = ((unsigned char *)seadp_header)+sizeof(seadp_hdr_t);
            int pk_mtu = htons(info->req_info->MTU);
            int mtu_len = set_tlv_header(TLV_MTU, tlv_buff,&pk_mtu, 2);
            if(nop>0){
                bzero(tlv_buff+mtu_len,(size_t)nop);
            }
            // }
            int csum = get_seadp_checksum(seadp_header,NULL,0);
            seadp_header->checksum = (uint32_t)csum;
            req_packet->buff = (uint8_t*)seadp_header;
            #ifdef USECC
            cc_req_packet_t cc_rpt;
            cc_rpt.packet_no = info->packet_number;
            cc_rpt.totalsize = req_packet->req_data_size;
            SEADP_DBG( DBG_LEVEL_TRACE,"send req end !\n");
            seadp_cc_add_packet(info->cc,&cc_rpt);
            #else
            seadp_rpt_output(info, info->packet_number);
            #endif
            if(info->packet_number == 65000){
                SEADP_DBG( DBG_LEVEL_ERROR,"-----------------------packet number out\n");
                info->packet_number = 2;
                info->abandon_packet_number=1;
                //exit(0);
            }
            info->packet_number++;

        }

    }else{
        return -1;
    }
    return 0;
}

static long int get_rto(seadp_receiver_info_t * info, unsigned long packetnumber,uint64_t etime_ms){

    int dt= (int)(etime_ms-info->req_info->req_packet[packetnumber]->send_time);
    if(info->req_info->req_packet[packetnumber]->stat != 2){
        return 0;
        //dt=dt+1;
    }
    if(dt<50){
        dt=50;
    }
    info->RTO_PT = (dt+4*info->RTO_PT)/5;
    SEADP_DBG( DBG_LEVEL_TRACE,"RTO a %u\n",info->RTO_PT);
    return 0;
}

static void receiver_process_packets(void * void_info,struct rte_mbuf *mbuf){
    seadp_receiver_info_t *info = (seadp_receiver_info_t*)void_info;
    int len = rte_pktmbuf_data_len(mbuf);
    if(len<IPV6_HDR_LEN-ID_HDR_LEN+SEADP_HDR_LEN){
        goto end;
    }
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ipv6_hdr_t *ipv6_hdr = ( ipv6_hdr_t *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));
    id_hdr_t *id_hdr = ( id_hdr_t *)RTE_PTR_ADD(ipv6_hdr, sizeof(ipv6_hdr_t));
    seadp_hdr_t *rcv_seadp = (seadp_hdr_t *)RTE_PTR_ADD(id_hdr, sizeof(id_hdr_t));
   
    int real_len = len - IPV6_HDR_LEN -ID_HDR_LEN;
    if(info->local_port != rcv_seadp->dstPort){
        goto end;
    }

    int seadp_checksum=-1;
    seadp_checksum=get_seadp_checksum(rcv_seadp,((uint8_t*)rcv_seadp + rcv_seadp->hdrlen),real_len-rcv_seadp->hdrlen);
    if(seadp_checksum!=0){
        SEADP_DBG( DBG_LEVEL_ERROR,"seadp checksum error= %x\n",(uint32_t)seadp_checksum);
        goto end;
    }
    SEADP_DBG( DBG_LEVEL_TRACE,"rcv dstport : %u\n",ntohs(rcv_seadp->dstPort));
    if(info->req_info->req_packet[ntohs(rcv_seadp->packetnumber)]!=NULL){
        int payload_len=0;
        if (rcv_seadp->pflag==DAT||rcv_seadp->pflag==CDAT){
            unsigned char *packet = ((unsigned char *)rcv_seadp);
            if(rcv_seadp->pflag==CDAT){
                info->Port = rcv_seadp->srcPort;
                if(info->chunksize==0){
                    info->buff = get_chunk_buf(info->cb_ptr,ntohl(rcv_seadp->len));
                    SEADP_DBG( DBG_LEVEL_TRACE,"info->buff size %d\n",ntohl(rcv_seadp->len));
                    size_t po=ntohl(rcv_seadp->off);
                    payload_len=real_len- rcv_seadp->hdrlen;
                    recv_first_packet(info,(uint32_t)ntohl(rcv_seadp->len),(uint32_t)(ntohl(rcv_seadp->off)+payload_len-1));  //need modify
                    rte_memcpy(info->buff+po,packet+rcv_seadp->hdrlen,(size_t)payload_len);
                }else{
                    rte_free(info->req_info->req_packet[1]);
                    info->req_info->req_packet[1]=NULL;
                }
            }else{
                SEADP_DBG( DBG_LEVEL_TRACE,"chunksize: %lu\n",info->chunksize);
                SEADP_DBG( DBG_LEVEL_TRACE,"rcv segment!!!len %d\n",real_len);
                size_t po=ntohl(rcv_seadp->off);
                payload_len=real_len-rcv_seadp->hdrlen;
                rte_memcpy(info->buff+po,packet+rcv_seadp->hdrlen,(size_t)payload_len);
                recv_packet_t recv_packet;
                recv_packet.packet_num=ntohs(rcv_seadp->packetnumber);
                recv_packet.left_off=ntohl(rcv_seadp->off);
                recv_packet.right_off=(uint32_t)(ntohl(rcv_seadp->off)+payload_len-1);     //need modify
                get_rto(info,recv_packet.packet_num,mbuf->timestamp/1000000LL);
                inform_recv_packet(info,&recv_packet,1);  //need modify
                #ifdef USECC
                data_packet_t data_packet;
                data_packet.packet_no =recv_packet.packet_num;
                data_packet.offset =recv_packet.left_off;
                data_packet.size =recv_packet.right_off-recv_packet.left_off+1;
                data_packet.recv_ts=mbuf->timestamp/1000000LL;
                seadp_cc_on_feedback(seadp_info->cc, &data_packet);
                #endif
            }
        }
    }else if( ntohs(rcv_seadp->packetnumber) <= info->abandon_packet_number){
        SEADP_DBG( DBG_LEVEL_TRACE," rcv NULL;\n");
        info->RTO_PT = (info->RTO_PT+50)%10000;
    }else{
        info->RTO_PT = (info->RTO_PT+100)%10000;
    }
end:
    return;
}
