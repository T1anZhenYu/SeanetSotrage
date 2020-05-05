#include <stdio.h>
#include <stdlib.h> //for malloc(), free()
#include <string.h> //for strstr(), memset()
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <pthread.h>

#include "seaep_log.h"
#include "seaep_loop.h"
#include "Defaults.h"
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_ether.h>

#define MAGIC_NUMBER 0X9999

typedef struct global_seaep_info_{
    char c1_node[128];
    char delay_level;
    void *ring_context;
    int magic_num;
}global_seaep_info;

global_seaep_info global_info;



int eth_send(void * ring_context, unsigned char *eth_packetbuff, unsigned int len)
{

    sendpacket *ep_packet;
    unsigned socket;
    unsigned lcore_id;

    lcore_id = rte_lcore_id();
    socket = rte_lcore_to_socket_id(lcore_id);
    ep_packet =  rte_zmalloc_socket("SEAEP", sizeof(struct sendpacket), RTE_CACHE_LINE_SIZE, socket);
     if (ep_packet == NULL)
    {
        printf("the struct sendpacket to tx core malloc fail!\n");
        return -1;
    }
    //rte_memcpy(ep_packet-);
    ep_packet->len = len ;
    ep_packet->packet = eth_packetbuff;
    ep_packet->type = SEAEP_TYPE;
   
    // printf("\neth_send len: %d\n data:\n", len);
    //unsigned int i;
    //for(i=0;i<len;i++)
    //    printf("%x ",eth_packetbuff[i]);
    //printf("\n");

	//printf("this packet have finish dispatch work! \n\n");
	if (rte_ring_enqueue(ring_context, (void *)ep_packet) < 0)
	{
		RTE_LOG(DEBUG, EAL, "[MOBILE LCORE]:Not enough room in the ring to enqueue on socket\n");
		return -1;
	}

    return 0;
}

void delete_seaep_action_record(seaep_action_record * item);

int get_local_ip6addr(unsigned char ip[16])
{
    /*
    ip[0] = 0xfe;
    ip[1] = 0x80;
    ip[2] = 0x00;
    ip[3] = 0x00;
    ip[4] = 0x00;
    ip[5] = 0x00;
    ip[6] = 0x00;
    ip[7] = 0x00;
    ip[8] = 0x46;
    ip[9] = 0xa8;
    ip[10] = 0x42;
    ip[11] = 0xff;
    ip[12] = 0xfe;
    ip[13] = 0x07;
    ip[14] = 0xc3;
    ip[15] = 0x7c;
    */
    //2400:dd01:1037:101:192:168:101:12
    ip[0] = 0x24;
    ip[1] = 0x00;
    ip[2] = 0xdd;
    ip[3] = 0x01;
    ip[4] = 0x10;
    ip[5] = 0x37;
    ip[6] = 0x01;
    ip[7] = 0x01;
    ip[8] = 0x01;
    ip[9] = 0x92;
    ip[10] = 0x01;
    ip[11] = 0x68;
    ip[12] = 0x01;
    ip[13] = 0x01;
    ip[14] = 0x00;
    ip[15] = 0x12;
    return 0;
}


typedef struct mac_table_ 
{
    const char *na;
    const char mac[6];
}mac_table;


mac_table global_mac_table[]={
    {"1:1:1:1:1:1:1:5",{0x44,0xa8,0x42,0x0f,0xbb,0x5a}/*"44:a8:42:0f:bb:5a"*/},
    {"1:1:1:1:1:1:1:1",{0x44,0xa8,0x42,0x0f,0xbb,0x5a}/*"44:a8:42:0f:bb:5a"*/},
    {"2400:dd01:1037:101:192:168:101:8",{0xb4,0x96,0x91,0x49,0xe5,0x6f}/*"b4:96:91:49:e5:6f"*/},
    {"2400:dd01:1037:101:192:168:101:16",{0xac,0x16,0x2d,0xb6,0xd8,0xfd}/*"ac:16:2d:b6:d8:fc"*/},
    {"2400:dd01:1037:101:192:168:101:240",{0xac,0x16,0x2d,0xb6,0xd8,0xfd}/*"ac:16:2d:b6:d8:fc"*/},
    {"2400:dd01:1037:101:192:168:101:241",{0xac,0x16,0x2d,0xb6,0xd8,0xfd}/*"ac:16:2d:b6:d8:fc"*/},
    {"2400:dd01:1037:101:192:168:101:242",{0xb8,0x2a,0x72,0xd3,0x70,0x89}/*"b8:2a:72:d3:70:89"*/},
    {"2400:dd01:1037:101:192:168:101:243",{0xb8,0x2a,0x72,0xd3,0x70,0x89}},
};

const char * get_host_mac(const char *hostip)
{
    int i=0;
    for(i=0;i<sizeof(global_mac_table)/sizeof(mac_table);i++)
    {
        if(strcmp(hostip,global_mac_table[i].na)==0)
            return global_mac_table[i].mac;
    }

    return NULL;
}


unsigned int current_time_ms(void)
{
    struct timeval tv;
    struct timezone tz;

    gettimeofday (&tv , &tz);
                
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

void fill4(unsigned char *p, unsigned int n)
{
    p[0] = (n & 0xff000000)>>24;
    p[1] = (n & 0x00ff0000)>>16;
    p[2] = (n & 0x0000ff00)>>8;
    p[3] = (n & 0x000000ff);
}


static int addr_is_ipv4(char ip_addr[16])
{
    int value = 0,i;
    for(i=0;i<12;i++){
        value|=ip_addr[i/*+4*/];
    }
    if(!value){
        return 1;
    }
    return 0;
}



static char port_map[TOTAL_PORT_NUM];

int init_seaep_port_resource()
{
    memset(port_map,0,TOTAL_PORT_NUM);
    return 0;
}

unsigned short get_avail_seaep_port()
{
    int i=0;
    unsigned short port = 0;

    for(i=0;i<TOTAL_PORT_NUM;i++)
    {
        if(port_map[i]==0)
        {
            port_map[i] = 1; 
            port = MIN_APP_PORT+i;
            break;
        }
    }
    return port;
}

int seaep_port_is_available(unsigned short port)
{
    int avail = 0;

    if(port <MIN_APP_PORT||port>MAX_APP_PORT){
        return avail;
    }
    avail = !(port_map[port -MIN_APP_PORT]);
    return avail;
}

int seaep_port_is_available_set(unsigned short port)
{
    int avail = 0;

    if(port <MIN_APP_PORT||port>MAX_APP_PORT){
        return avail;
    }
    avail = !(port_map[port -MIN_APP_PORT]);
    if(avail)
        port_map[port -MIN_APP_PORT] = 1;
    return avail;
}



void release_seaep_port(unsigned short port)
{
    if(port <MIN_APP_PORT||port>MAX_APP_PORT){
        return ;
    }
    port_map[port -MIN_APP_PORT] = 0;
    return ;
}


seaep_action_record * seaep_action_record_head = NULL;

int add_seaep_action_record(seaep_action_record * new_record)
{

    if(seaep_action_record_head == NULL)
          seaep_action_record_head = new_record;
    else{
        seaep_action_record *item = seaep_action_record_head;
        while(item->next){
            item = item->next;
        }
        item->next = new_record;
    }
    return 0;

}

void print_seaep_action_record()
{
    seaep_action_record *item = seaep_action_record_head;

    seaep_log("list:  ");

    while(item)
    {
        seaep_log(" %p > ",item);
        item = item->next;
    }  

    seaep_log("end\n");

}


int remove_seaep_action_record(seaep_action_record * new_record)
{
    seaep_action_record *item = seaep_action_record_head;

    if(!item || !new_record)
        return -1;

    if(seaep_action_record_head == new_record)
    {
        seaep_action_record_head = new_record->next;
    }
    else{
        while(item->next)
        {
            if(item->next == new_record)
            {
                item->next = item->next->next;
                break;
            }
            item = item->next;
        }
    }


    delete_seaep_action_record(new_record);


    return 0;
}


seaep_action_record* get_seaep_action_record(unsigned short port, int *num)
{
    int i;
    seaep_action_record *item = seaep_action_record_head;

    while(item)
    {
        for(i=0;i<item->result.node_num;i++){
            if(item->result.node_info[i].local_port == port)
            {
                *num = i;
                return item;
            }
        }
        item = item->next;
    }
    return NULL;
}


void delete_seaep_action_record(seaep_action_record * item)
{
    if(!item)
        return;
    int i=0;

    if(item->result.node_info){
        for(i=0;i<item->result.node_num;i++)
            release_seaep_port(item->result.node_info[i].local_port);
        free(item->result.node_info);
        item->result.node_info = NULL;
    }

    if(item->result.na_info){
        delete_na_list(item->result.na_info);
        item->result.na_info = NULL;
    }
    return ;    
}

static unsigned long long get_mstime(void)
{
	static int firsttimehere=1;
	static struct timeval timeorigin;

	struct timeval now;

	// the first time, set the origin.
	if (firsttimehere) {
		gettimeofday(&timeorigin,NULL);
		firsttimehere=0;
	}

	gettimeofday(&now,NULL);

	return (unsigned long long)(
		 (
		  (long long)now.tv_sec
		  -(long long)timeorigin.tv_sec
		  )*1000000LL
		 +
		 ( 
		  (long long)now.tv_usec
		  -(long long)timeorigin.tv_usec
		  )
		 )/1000;
}



static unsigned short fill_udp_checksum(unsigned char srcIP[16],unsigned char dstIP[16],unsigned char *udp_header,unsigned char *payload_buff,size_t payload_len)
{
    unsigned char *buffer;
    UDP_HDR *udpHEADER = (UDP_HDR *)udp_header;

    buffer = (unsigned char *)malloc(40+UDP_HDR_LEN+payload_len);
    if( buffer == NULL )
    {
        return -1;
    }

    bzero(buffer+34,5);
    memcpy(buffer,srcIP,16);
    memcpy(buffer+16,dstIP,16);
    memcpy(buffer+32,&(udpHEADER->totalLenOfPacket),2);
    buffer[39] = 0x11;
    memcpy(buffer+40, udpHEADER, UDP_HDR_LEN);
    memcpy(buffer+48, payload_buff, payload_len);

    size_t size = 40+UDP_HDR_LEN+payload_len;
    unsigned long cksum = 0;
    unsigned short *t_buffer = buffer;
    while(size>1)
    {
        cksum += *t_buffer++;
        size -= sizeof(unsigned short);
    }
    if(size)
    {
        cksum += *(unsigned char*)t_buffer;
    }
    cksum = (cksum>>16) + (cksum&0xffff);
    cksum += (cksum>>16);

    free(buffer);
    return (unsigned short)(~cksum);
}


int send_udp_data(unsigned char *data_buffer,int data_len,unsigned short local_port, unsigned short  dst_port, unsigned char src_addr[16], unsigned char dst_addr[16])
{
    int i;
    ssize_t len=-1;
    

    unsigned char *packetbuff= (unsigned char *)malloc(UDP_HDR_LEN+IPV6_HDR_LEN+sizeof(struct ether_hdr )+data_len);
    if( packetbuff == NULL )
    {
        return -1;
    }

    struct ether_hdr *eth =(struct ether_hdr *)packetbuff;
    char addr[128];
    inet_ntop(AF_INET6, dst_addr, addr, sizeof(addr));
    const char *mac = get_host_mac(addr);
    if(!mac){
        seaep_err("no such mac  for host %s\n",addr);
        return -1;
    }

    for (i = 0; i < 6; i++)
    {
        eth->d_addr.addr_bytes[i] = mac[i];
    }

//90:e2:ba:86:42:3d
    eth->s_addr.addr_bytes[0] = 0x90;
    eth->s_addr.addr_bytes[1] = 0xe2;
    eth->s_addr.addr_bytes[2] = 0xba;
    eth->s_addr.addr_bytes[3] = 0x86;
    eth->s_addr.addr_bytes[4] = 0x42;
    eth->s_addr.addr_bytes[5] = 0x3d;

    eth->ether_type = htons(ETHER_TYPE_IPv6);

    UDP_HDR *udp_header = (UDP_HDR *)(packetbuff+IPV6_HDR_LEN+sizeof(struct ether_hdr));
    udp_header->srcPort = ntohs(local_port);
    udp_header->dstPort = ntohs(dst_port);
    udp_header->totalLenOfPacket = htons(UDP_HDR_LEN+data_len);
    udp_header->checkSum = 0x0000;

    udp_header->checkSum = fill_udp_checksum(src_addr,dst_addr,(unsigned char *)udp_header,data_buffer, data_len);

    IPv6_HDR *ip_header = (IPv6_HDR *)(packetbuff+sizeof(struct ether_hdr));
    ip_header->version=6;
    ip_header->trafficClass=0;
    bzero(ip_header->flowLable,3);
    ip_header->payloadLength = htons(UDP_HDR_LEN+data_len);
    ip_header->protocol = 0x11;
    ip_header->hopLimit = 0xff;
    memcpy(ip_header->srcAddr,src_addr, 16);
    memcpy(ip_header->dstAddr,dst_addr, 16);


    memcpy(packetbuff+IPV6_HDR_LEN+UDP_HDR_LEN+sizeof(struct ether_hdr),data_buffer, data_len);

    if(mac){
        len = eth_send(global_info.ring_context, packetbuff,IPV6_HDR_LEN+UDP_HDR_LEN+data_len+sizeof(struct ether_hdr));
    	//seaep_info("dst mac is %s\n",mac);
    }else
        seaep_err("no such mac  for host %s\n",dst_addr);

    //free(packetbuff);
    return len;
}


int parse_ring_packet(unsigned char *data_buff,unsigned int len , packet* newpacket)
{
    if(len <= IPV6_HDR_LEN+UDP_HDR_LEN || !newpacket)
        return -1;



    IPv6_HDR *ip_header=(IPv6_HDR *)data_buff;
    UDP_HDR *udp_header = (UDP_HDR *)(data_buff+IPV6_HDR_LEN);
/*
    seaep_log("srcport: %d dstPort: %d\n",ntohs(udp_header->srcPort), ntohs(udp_header->dstPort));

     seaep_log("src_addr: ");
     int k;
     for (k = 0; k < 16; k++){   
     seaep_log("%02x", ip_header->srcAddr[k]);
     }
     seaep_log("\n");

    seaep_log("dst_addr: ");
    for (k = 0; k < 16; k++){   
    seaep_log("%02x", ip_header->dstAddr[k]);
    }
    seaep_log("\n");
*/
    memcpy(newpacket->dst_na_ip,ip_header->dstAddr,16);
    memcpy(newpacket->src_na_ip,ip_header->srcAddr,16);

    newpacket->src_port = ntohs(udp_header->srcPort);
    newpacket->dst_port = ntohs(udp_header->dstPort);
    newpacket->data_len = len-IPV6_HDR_LEN-UDP_HDR_LEN;
    newpacket->data_buf = data_buff+IPV6_HDR_LEN+UDP_HDR_LEN;
    //seaep_log("get_ring_packet ok.\n");

    return 0;
}


int send_out_data(seaep_action_record * item,server_info *  serverlist, int listnum, unsigned char *data_buffer, int data_len)
{
    int i;


    item->result.node_num = listnum;
    item->result.node_info = (node_list_info *)malloc(sizeof(node_list_info)*listnum);

    //seaep_log("send_out_data item->result.node_num %d\n",item->result.node_num);

    for(i=0;i<listnum;i++){   
        strncpy(item->result.node_info[i].resolution_node_addr,serverlist[i].server_addr,NASTR_MAX_LEN);
        unsigned short local_port = get_avail_seaep_port();
        item->result.node_info[i].local_port = local_port;
        unsigned char local_na[16], dst_na[16];
        get_local_ip6addr(local_na);
        inet_pton(AF_INET6,(char *)serverlist[i].server_addr,dst_na);
        send_udp_data(data_buffer,data_len,local_port,serverlist[i].port,local_na,dst_na);
    }
    delete_register_server_list(serverlist,listnum);
    if(item->result.type == SEAEP_ACTION_RESPONSE_UPDATE_RNL)
        item->action_time_out = get_mstime()+REQUEST_RNL_TIMEOUT;
    else
        item->action_time_out = get_mstime()+TASK_TIMEOUT;
    add_seaep_action_record(item);
    return 0;
}

#include <sys/ioctl.h>
static char * netbytes2ip(char *ip)
{
    static char buf[128];

    if(addr_is_ipv4((char *)ip))
    {
        in_addr_t addr; 
        int j; 
        char *addr_data =(char *)ip;
        char *y = (char *)&addr; 
        for(j=0;j<4;j++){
            y[j] = addr_data[j+12];      
        } 
        if(inet_ntoa(*(struct in_addr *)&addr)) 
            return inet_ntoa(*(struct in_addr *)&addr);
    }else{
        struct sockaddr_in6 dst;
        dst.sin6_family =AF_INET6;
        dst.sin6_port = 0;
        dst.sin6_flowinfo = 0;
        dst.sin6_scope_id = 0;
        memcpy(&dst.sin6_addr,ip,16);

        
        memset(buf,0,128);
        inet_ntop(AF_INET6,&dst.sin6_addr,buf,sizeof(buf));

        //seaep_log("send to ipv6 addr %s\n",inet_ntop(AF_INET6,&dst.sin6_addr,buf,sizeof(buf)));
     /*
        char str[INET6_ADDRSTRLEN];
        if(inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN) == NULL){    
            return NULL;
        }
        */
        //seaep_log("str is %s\n",buf);
        return buf;

    }
    return NULL;
}


int seaep_process_request_rnl_msg(char *recv_data, int len)
{
    int pos=0,i;

    char type = recv_data[pos];
    pos ++;

    char status = recv_data[pos];
    pos ++;
    seaep_info("seaep_process_update_rnl_msg type is %d, status %d\n",type,status);
    if(type != SEAEP_ACTION_RESPONSE_UPDATE_RNL||status !=STATUS_OK )
        return -1;

    rn_list new_rnlist;
    initialize_rnl_list(&new_rnlist);

    rn_list *list = &new_rnlist;//get_rn_list();

    list->delaylevel_num = recv_data[pos];
    pos ++;    

    list->pdelay_item = (delay_item*)malloc(sizeof(delay_item)*list->delaylevel_num);
    if(!list->pdelay_item){
        return -1;
    }
    for(i=0;i<list->delaylevel_num;i++)
    {
        list->pdelay_item[i].delaylevel= recv_data[pos];
        pos ++;

        list->pdelay_item[i].delay_parms = recv_data[pos];
        pos ++;
    }
    
    list->resolve_node_num = recv_data[pos];
    pos ++;    
    
    if(pos + list->resolve_node_num*21 >len){
        return -1;
    }

     list->presolve_node = (resolve_node_inuse*)malloc(sizeof(resolve_node_inuse)*list->resolve_node_num);
     if(!list->presolve_node){
        return -1;
    }
    //seaep_log("list->resolve_node_num  %d\n",list->resolve_node_num );

    for(i=0;i<list->resolve_node_num;i++)
    {    
        list->presolve_node[i].delaylevel= recv_data[pos];
        pos ++;
        
        //pos ++;
        
        memcpy(list->presolve_node[i].id,recv_data+pos,4);
        pos += 4;
        
        char *ip = netbytes2ip(recv_data+pos);
        if(ip)
        {
            strcpy(list->presolve_node[i].na,ip);
        }
        pos += 16;   

        int j;
        for(j=i;j>=1;j--)//sort by level
        {
            if(list->presolve_node[j].delaylevel < list->presolve_node[j-1].delaylevel)
            {                
                resolve_node_inuse tmp_resolve_node;
                memcpy(&tmp_resolve_node,&list->presolve_node[j],sizeof(resolve_node_inuse));
                memcpy(&list->presolve_node[j],&list->presolve_node[j-1],sizeof(resolve_node_inuse));
                memcpy(&list->presolve_node[j-1],&tmp_resolve_node,sizeof(resolve_node_inuse));
            }
            else
                break;
        }
    
     }

//child node    
     list->child_node_num = recv_data[pos];
     pos ++;    
    
     if(pos + list->child_node_num*21 >len){
        return -1;
    }

     list->pchild_node = (child_node*)malloc(sizeof(child_node)*list->child_node_num);
     if(!list->pchild_node){
        return -1;
    }

    for(i=0;i<list->child_node_num;i++)
    {    
        list->pchild_node[i].delaylevel= recv_data[pos];
        pos ++;        
        
        memcpy(list->pchild_node[i].id,recv_data+pos,4);
        pos += 4;
        
        char *ip = netbytes2ip(recv_data+pos);
        if(ip)
        {
            strcpy(list->pchild_node[i].na,ip);
        }
        pos += 16;   

        int j;
        for(j=i;j>=1;j--)//sort by level
        {
            if(list->pchild_node[j].delaylevel < list->pchild_node[j-1].delaylevel)
            {                
                child_node tmp_child_node;
                memcpy(&tmp_child_node,&list->pchild_node[j],sizeof(child_node));
                memcpy(&list->pchild_node[j],&list->pchild_node[j-1],sizeof(child_node));
                memcpy(&list->pchild_node[j-1],&tmp_child_node,sizeof(child_node));
            }
            else
                break;
        }
    
     }
    
     list->neighbor_node_num = recv_data[pos];
     pos ++;    
     //seaep_log("list->neighbor_node_num  %d\n",list->neighbor_node_num);
      if(pos + list->neighbor_node_num*20 >len){
         return -1;
     }


     if(list->neighbor_node_num >0){
         list->pneighbor_node= (neighbor_node*)malloc(sizeof(neighbor_node)*list->neighbor_node_num);
         
          if(!list->pneighbor_node){
            return -1;
         }

         for(i=0;i<list->neighbor_node_num;i++)
         {
             memcpy(list->pneighbor_node[i].id,recv_data+pos,4);
             pos += 4;
        
             char *ip = netbytes2ip(recv_data+pos);
             if(ip)
             {
                 strcpy(list->pneighbor_node[i].na,ip);
             }
        
             //memcpy(list->pneighbor_node[i].na,recv_data+pos,16);
             pos += 16;
         }
    }
   // seaep_log("timestamp is %u\n",combin4((unsigned char *)recv_data+pos));
    update_resolver_list(list);
    
    print_resolver_list();
    seaep_log("seaep_process_update_rnl_msg return  is %p\n","OK");

    return 0;//list;
}



int seaep_request_rnl(const char *c1_node,unsigned short port, char delay_level)
{
    unsigned char data_buffer[256];
    int data_len =0;
    int ret =-1;
    //seaep_info("seaep_request_rnl server addr %s port %d delaylevel %d\n", c1_node, port,delay_level);

    seaep_action_record * newone = (seaep_action_record *)malloc(sizeof(seaep_action_record));

    memset(newone,0,sizeof(seaep_action_record));
    newone->result.type = SEAEP_ACTION_RESPONSE_UPDATE_RNL;
    newone->result.finished = 0;


    //type
    data_buffer[data_len] = SEAEP_ACTION_UPDATE_RNL;
    data_len +=1;

    //delay level
   // data_buffer[data_len] = delaylevel;
   // data_len +=1;//discard

    //timestamp
    unsigned int ms = current_time_ms();
    fill4(data_buffer+data_len,ms);
    data_len += 4;

    int listnum = 1;
    server_info *serverlist=(server_info *)malloc(sizeof(server_info));
    serverlist->port = port;
    strcpy(serverlist->server_addr,c1_node);

    send_out_data(newone, serverlist, listnum, data_buffer, data_len);

/*


    int ret1 = send_udp_data(data_buffer, data_len, local_port, port, (unsigned char *)na, (unsigned char *)dst_na);

    seaep_log("send udp data %d\n",ret1);
    if(ret1 > 0)
    {
        unsigned long long time_out =get_mstime()+TASK_TIMEOUT;
        while(1)
        {
            if(get_mstime() > time_out)
            {
                seaep_err("err happen, time out for request rnl \n");
                break;
            }
            packet *p = get_ring_packet();
            if(p && (p->dst_port == local_port))
            {
               ret = seaep_process_request_rnl_msg((char *)p->data_buf, p->data_len);
               break;
            }
        }
    }
    release_seaep_port(local_port);
*/
    return ret;
}



int  seaep_init(void *ring_context, const char *global_resolve_node, const char *c1_node,  int delay_level, int rnl_update_interval)
{
    int ret = -1;
    global_info.magic_num = MAGIC_NUMBER;
    strcpy(global_info.c1_node, c1_node);
    global_info.ring_context = ring_context;
    global_info.delay_level = delay_level;


    init_seaep_port_resource();
    if(global_resolve_node)
        update_global_resolve_addr(global_resolve_node);


    if(c1_node){
    //just for test
#ifdef TESTLINUX
    int recv_data();

    pthread_t subpid;
    ret = pthread_create(&subpid, NULL, recv_data, NULL);
#endif 

    ret = seaep_request_rnl(c1_node,delay_level+SERVER_BASE_PORT,delay_level);
    }
  
    return ret;
}


int seaep_start_register (char eid[EID_LEN],  void *context,int delayParameter,unsigned char ttl, int isGlobalVisable,Result_func_cb cb_func)
{
    
    if(global_info.magic_num != MAGIC_NUMBER)
    {
        seaep_info("init should be done first\n");
        return -1;
    }
    seaep_action_record * newone = (seaep_action_record *)malloc(sizeof(seaep_action_record));

    memset(newone,0,sizeof(seaep_action_record));
    newone->cb_func = cb_func;
    newone->context = context;
    newone->result.type = SEAEP_ACTION_RESPONSE_RIGSTER;
    newone->result.finished = 0;
    memcpy(newone->result.eid,eid,EID_LEN);   



    //seaep_info("seaep_register start\n");
    unsigned char data_buffer[256];
    int data_len =0;

// console log
    char log_buffer[256];
    memset(log_buffer,0,sizeof(log_buffer));
    strcat(log_buffer,"eid is: ");
    int i=0;
    for(i=0;i<EID_LEN;i++)
        sprintf(log_buffer+strlen(log_buffer),"%.2x ",((unsigned char*)eid)[i]);
    strcat(log_buffer," \n");
    //seaep_info("seaep_resolve eid is %s\n",log_buffer);

//type
    data_buffer[data_len] = SEAEP_ACTION_REGISTER;
    data_len +=1;

//eid
    memcpy(data_buffer+data_len,eid,20);
    data_len += 20;

    char na[16];
    get_local_ip6addr(na);

    memcpy(data_buffer+data_len,na,16);
    data_len += 16;

//delayParameter
    unsigned char level = get_delay_level(delayParameter);
    memcpy(data_buffer+data_len,&level,1);
    data_len += 1;

//ttl 
    memcpy(data_buffer+data_len,&ttl,1);
    data_len += 1;

//mflag
    data_buffer[data_len] = 0;
    data_len += 1;  

//timestamp 
    unsigned int ms = current_time_ms();

    memcpy(data_buffer+data_len,&ms ,4);
    data_len += 4;

    int listnum = 0;
    server_info *  serverlist = get_register_server_list_lowlevel(&listnum,isGlobalVisable,delayParameter);
    //seaep_log("server list  listnum %d\n",listnum);  

    if(serverlist){
        send_out_data(newone, serverlist, listnum, data_buffer, data_len);
    }else{    
        //seaep_info("seaep_register no available resolve id\n");
        free(newone);
    }

    return 0;
}

int seaep_start_resolve (char eid[EID_LEN], void *context, int delayParameter,Result_func_cb cb_func)
{
    if(global_info.magic_num != MAGIC_NUMBER)
    {
        seaep_info("init should be done first\n");
        return -1;
    }

    seaep_action_record * newone = (seaep_action_record *)malloc(sizeof(seaep_action_record));

    memset(newone,0,sizeof(seaep_action_record));
    newone->cb_func = cb_func;
    newone->context = context;
    newone->result.type = SEAEP_ACTION_RESPONSE_RESOLVE;
    newone->result.finished = 0;
    memcpy(newone->result.eid,eid,EID_LEN);   

    //seaep_info("seaep_resolve start to delayParameter %d\n",delayParameter);
    unsigned char data_buffer[256];
    int data_len =0;


// console log
    char log_buffer[256];
    memset(log_buffer,0,sizeof(log_buffer));
    strcat(log_buffer,"eid is: ");
    int i=0;
    for(i=0;i<EID_LEN;i++)
        sprintf(log_buffer+strlen(log_buffer),"%.2x ",((unsigned char*)eid)[i]);
    strcat(log_buffer," \n");
    seaep_info("seaep_resolve eid is %s\n",log_buffer);

    //type
    data_buffer[data_len] = SEAEP_ACTION_RESOLVER;
    data_len +=1;

    //eid
    memcpy(data_buffer+data_len,eid,20);
    data_len += 20;

    //timestamp
    unsigned int ms = current_time_ms();
    memcpy(data_buffer+data_len,&ms ,4);
    data_len += 4;

    int listnum = 0;
    server_info *  serverlist = get_register_server_list(&listnum,1,delayParameter);

    if(serverlist){
        send_out_data(newone, serverlist, listnum, data_buffer, data_len);
    }else{    
        seaep_info("seaep_register no available resolve id\n");
        free(newone);
    }

    return 0;
}


int seaep_start_unregister (char eid[EID_LEN],void *context, Result_func_cb cb_func)
{
    if(global_info.magic_num != MAGIC_NUMBER)
    {
        seaep_info("init should be done first\n");
        return -1;
    }

    seaep_action_record * newone = (seaep_action_record *)malloc(sizeof(seaep_action_record));

    memset(newone,0,sizeof(seaep_action_record));
    newone->cb_func = cb_func;
    newone->context = context;
    newone->result.type = SEAEP_ACTION_RESPONSE_LOGOUT;
    newone->result.finished = 0;
    memcpy(newone->result.eid,eid,EID_LEN);   

    unsigned char data_buffer[256];
    int data_len =0;

    seaep_info("seaep_unregister \n");

    //type
    data_buffer[data_len] = SEAEP_ACTION_LOGOUT;
    data_len +=1;

    //flag
   //mflag =1�������
    data_buffer[data_len] = 0;
    data_len +=1;

    //eid
    memcpy(data_buffer+data_len,eid,20);
    data_len += 20;

    //na
    char na[16];
    get_local_ip6addr(na);


    memcpy(data_buffer+data_len,na,16);
    data_len += 16;

    //timestamp
    unsigned int ms = current_time_ms();
    memcpy(data_buffer+data_len,&ms ,4);
    data_len += 4;

    int listnum = 0;

     server_info *  serverlist = get_register_server_list_lowlevel(&listnum,1,MAX_DELAY_TIME);

    if(serverlist){
        send_out_data(newone, serverlist, listnum, data_buffer, data_len);
    }else{    
        seaep_info("seaep_register no available resolve id\n");
        free(newone);
    }

    return 0;
}

int seaep_parse_register_msg(char *recv_data, int len)
{
    char status = recv_data[1];
    if(status ==STATUS_OK) return 1;
    return -1;
}

na_list_info *  seaep_parse_resolve_msg(char *recv_data, int len)
{
    int pos=0,i;
    if(len <2)
        return NULL;
    char type = recv_data[pos];
    pos ++;

    char status = recv_data[pos];
    pos ++;
    //seaep_info("seaep_process_resolve_msg type is %d, status %d\n",type,status);
    if(type != SEAEP_ACTION_RESPONSE_RESOLVE||status !=STATUS_OK )
        return NULL;

    pos+=20;//eid code

    na_list_info * info = (na_list_info * )malloc(sizeof(na_list_info));
    if(!info)
        return NULL;

    memset(info,0,sizeof(na_list_info));
    info->na_num = recv_data[pos];
    //seaep_info("seaep ip resolve info->na_num %d\n",info->na_num);

    pos ++;
    info->na_list=(char **)malloc(sizeof(char *)*info->na_num);
    for(i=0;i<info->na_num;i++)
    {
        info->na_list[i] = (char*)malloc(256);

        char *ip = netbytes2ip(recv_data+pos);
        if(ip)
        {
            //seaep_info("seaep ip resolve is %s\n",ip);
            strcpy(info->na_list[i],ip);
        }
        pos+= 16;
     }
    //printf("seaep_process_resolve_msg return %p\n",info);
    return info;
}


int seaep_parse_unregister_msg(char *recv_data, int len)
{
    char status = recv_data[1];
    return (status ==STATUS_OK);
}

void check_expire_record()
{
    seaep_action_record *item = seaep_action_record_head;

    while(item)
    {
        if(item->action_time_out <= get_mstime())       
        {
            //seaep_info("check_expire_record happened  type %d\n",item->result.type);
             if(item->cb_func)
                item->cb_func(item->context,&item->result);      
             remove_seaep_action_record(item);  
             if(item->result.type == SEAEP_ACTION_RESPONSE_UPDATE_RNL)
                seaep_request_rnl(global_info.c1_node,global_info.delay_level+SERVER_BASE_PORT,global_info.delay_level);
                
        }
        item = item->next;
    }
    return;
}


void seap_loop(struct rte_mbuf *mbuf)
{
    int result;
    packet topacket;
    struct ether_hdr *eth_hdr;
    struct ipv6_hdr *ipv6_hdr2;

    int len;
    check_expire_record();
    
    if(!mbuf)
        return ;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    ipv6_hdr2 = (struct ipv6_hdr *)RTE_PTR_ADD(eth_hdr, sizeof(struct ether_hdr));

    len = ipv6_hdr2->payload_len;

   
    //get net packet from queue
    result = parse_ring_packet(ipv6_hdr2, len, &topacket);
    if(result >=0){
        int num = 0;
        seaep_action_record *record = get_seaep_action_record(topacket.dst_port,&num);

        switch(topacket.data_buf[0])
        {
            case SEAEP_ACTION_RESPONSE_RIGSTER:
                if(record){
                    result = seaep_parse_register_msg((char *)topacket.data_buf,topacket.data_len);
                    record->result.node_info[num].result = result;
                }
                break;
            case SEAEP_ACTION_RESPONSE_RESOLVE:
                if(record)
                {
                    na_list_info* list =  seaep_parse_resolve_msg((char *)topacket.data_buf,topacket.data_len);
                    if(list)
                    {
                         record->result.na_info = list;
                         record->result.node_info[num].result = 1;  
                         record->result.finished = 1;     
                         record->cb_func(record->context,&record->result); 

                         remove_seaep_action_record(record);
                    }else
                         record->result.node_info[num].result = -1;
                }
                break;  
            case SEAEP_ACTION_RESPONSE_LOGOUT:
                if(record){
                    result = seaep_parse_unregister_msg((char *)topacket.data_buf,topacket.data_len);
                    record->result.node_info[num].result = result;
                    //if(result >= 0)
                    	//remove_seaep_action_record(record);
                }
                break;
            case SEAEP_ACTION_RESPONSE_UPDATE_RNL:
                result = seaep_process_request_rnl_msg((char *)topacket.data_buf,topacket.data_len);
                if(result >= 0)
		    remove_seaep_action_record(record);
		break;
            default:
                seaep_info("unknown type %d\n",topacket.data_buf[0]);
                break;
      }
       
    }
    rte_pktmbuf_free(mbuf);
    return ;
}


