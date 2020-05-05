#include "resolve_name_list.h"
#include "seaep_log.h"
#include <stdio.h>
#include <stdlib.h> //for malloc(), free()
#include <string.h> //for strstr(), memset()
#include <sys/types.h>
#include <unistd.h>
//#include <pthread.h>

//pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

#define RNLMUTEX_LOCK      //{pthread_mutex_lock(&mutex); }
#define RNLMUTEX_UNLOCK    //{ pthread_mutex_unlock(&mutex); }


/*
#ȫ�����ֽ���ϵͳ��ַ
globalResolutionSystem=192.168.47.12
#��ǿ���ֽ���ϵͳ�н����ڵ�ʱ�ӵȼ�
delayLevels=1,2,3
#��ǿ���ֽ���ϵͳ�н����ڵ�ʱ����ֵ����λ����
delayParameters=10,50,100
#��ʹ�õ���ǿ���ֽ����ڵ�ʱ�ӵȼ�
delayLevelsInUse=1,2,3
#��ʹ�õ���ǿ���ֽ����ڵ�
IDresolverIdsInUse=879899,324983,928349
#��ʹ�õ���ǿ���ֽ����ڵ������ַ
resolverNasInUse=192.100.65.31,192.100.65.31,
192.100.65.33#��ײ�����ڵ��ھ�
IDneighborIds=456456,65756,345234,457456
#��ײ�����ڵ��ھ������ַ
neighborNas=192.100.65.32,192.100.65.34,192.100.65.35,192.100.65.36
#���ӽ����ڵ�ʱ�ӵȼ�
ChilddelayLevels=1,2,3
#���ӽ����ڵ�ID
ChilddelayIDS=879897,879895,879832
#���ӽ����ڵ������ַ
ChilddelayINA=192.100.65.32,192.100.65.34,192.100.65.35

*/


//#define TEST
#define TEST_RESOLVE_NODE_IP "192.168.10.23"//"2:2:2:2:2:2:2:2"
#define RNL_PORT 10063

//#define PORT_NUM 4

typedef struct local_rn_list_{
    rn_list global_rn_list;
    int global_valid;
    char global_resolve_addr[128];
}local_rn_list;

local_rn_list global_local_rn_list={0};


int print_resolver_list()
{
    int i;

    RNLMUTEX_LOCK

    //seaep_info("global_rn_list is_ipv4 %d\n",global_local_rn_list.global_rn_list.is_ipv4);
    seaep_info("rnl info start:\n ");

    seaep_info("    global_resolve_addr %s\n",global_local_rn_list.global_resolve_addr);

    for(i=0;i<global_local_rn_list.global_rn_list.delaylevel_num;i++)
        seaep_info("    delay_item[%d] delaylevel %d delay_parms %d\n",i,global_local_rn_list.global_rn_list.pdelay_item[i].delaylevel,global_local_rn_list.global_rn_list.pdelay_item[i].delay_parms);

   for(i=0;i<global_local_rn_list.global_rn_list.child_node_num;i++)
       seaep_info("    child_node_num[%d] delaylevel %d na %s\n",i,global_local_rn_list.global_rn_list.pchild_node[i].delaylevel,global_local_rn_list.global_rn_list.pchild_node[i].na);

    
   for(i=0;i<global_local_rn_list.global_rn_list.resolve_node_num;i++)
        seaep_info("    resolve_node_num[%d] delaylevel %d na %s\n",i,global_local_rn_list.global_rn_list.presolve_node[i].delaylevel,global_local_rn_list.global_rn_list.presolve_node[i].na);
   
   for(i=0;i<global_local_rn_list.global_rn_list.neighbor_node_num;i++)
        seaep_info("    neighbor_node_num[%d]  na %s\n",i,global_local_rn_list.global_rn_list.pneighbor_node[i].na);

   seaep_info("rnl info end:\n ");

   RNLMUTEX_UNLOCK
   return 0;

}

int free_resolver_list()
{
    RNLMUTEX_LOCK

    if(global_local_rn_list.global_rn_list.pdelay_item){
        free(global_local_rn_list.global_rn_list.pdelay_item);
    }

    if(global_local_rn_list.global_rn_list.presolve_node){
        free(global_local_rn_list.global_rn_list.presolve_node);
    }

    if(global_local_rn_list.global_rn_list.pneighbor_node){
        free(global_local_rn_list.global_rn_list.pneighbor_node);
    }

    if(global_local_rn_list.global_rn_list.pchild_node){
        free(global_local_rn_list.global_rn_list.pchild_node);
    }
    memset(&global_local_rn_list.global_rn_list,0,sizeof(global_local_rn_list.global_rn_list));
    RNLMUTEX_UNLOCK
    return 0;

}


int get_delay_level(int delayparms)
{    
    int i;

    if(global_local_rn_list.global_rn_list.initialized)
    {
        for(i=global_local_rn_list.global_rn_list.delaylevel_num-1;i>=0;i--)
        {
            if(global_local_rn_list.global_rn_list.pdelay_item[i].delay_parms <= delayparms)
                return global_local_rn_list.global_rn_list.pdelay_item[i].delaylevel;
        }
    }

    return -1;
}

//��ȡlevel ��Ӧdelay parms
int get_delay_parms(int level)
{    
    int i;

    if(global_local_rn_list.global_rn_list.initialized)
    {
        for(i=0;i<global_local_rn_list.global_rn_list.delaylevel_num;i++)
        {
            if(global_local_rn_list.global_rn_list.pdelay_item[i].delaylevel == level)
                return global_local_rn_list.global_rn_list.pdelay_item[i].delay_parms;
        }
    }

    return -1;
}

int initialize_rnl_list(rn_list *prn_list)
{
    memset(prn_list,0,sizeof(rn_list));
    prn_list->initialized = 1;    
    return 0;
}

server_info *get_register_server_list_lowlevel(int *num, int isGlobalVisable,int delayParameter)
{
    int i;

#ifndef TEST
    int node_num= 0;
    server_info * pserverlist = NULL;

    RNLMUTEX_LOCK
    if(global_local_rn_list.global_rn_list.initialized){
        {
            if(get_delay_parms(global_local_rn_list.global_rn_list.presolve_node[0].delaylevel)<=delayParameter)
                node_num++;
        }   

        if(isGlobalVisable&&global_local_rn_list.global_valid)
            node_num++;

        seaep_log("get_register_server_list num %d delayParameter %d\n",node_num,delayParameter);

        pserverlist = (server_info *)malloc(sizeof(server_info)*node_num); 
        memset(pserverlist,0,sizeof(server_info)*node_num);   
        *num = node_num;

        //only lowest node
        {                
            if(get_delay_parms(global_local_rn_list.global_rn_list.presolve_node[0].delaylevel)<=delayParameter){
                strcpy(pserverlist[0].server_addr,global_local_rn_list.global_rn_list.presolve_node[0].na);
                pserverlist[0].port = SERVER_BASE_PORT+global_local_rn_list.global_rn_list.presolve_node[0].delaylevel;
            }
        }

        if(isGlobalVisable&&global_local_rn_list.global_valid)
        {
            //todo : add  a delay err record
            //if(node_num ==1)
                //;
            strcpy(pserverlist[node_num-1].server_addr,global_local_rn_list.global_resolve_addr);
            pserverlist[node_num-1].port = GLOBAL_RESOLVER_PORT;
        }
        
    }else if(isGlobalVisable&&global_local_rn_list.global_valid){
         server_info * pserverlist = (server_info *)malloc(sizeof(server_info)*(1));
         strcpy(pserverlist[0].server_addr,global_local_rn_list.global_resolve_addr);
         pserverlist[0].port = GLOBAL_RESOLVER_PORT;
        *num = 1;
    }
    RNLMUTEX_UNLOCK
    return pserverlist;
#else
 server_info * pserverlist = (server_info *)malloc(sizeof(server_info)*(1));
 strcpy(pserverlist[0].server_addr,/*"192.168.189.202"*/TEST_RESOLVE_NODE_IP);
 pserverlist[0].port = RNL_PORT;
*num = 1;
 return pserverlist;

#endif
}



server_info *get_register_server_list(int *num, int isGlobalVisable,int delayParameter)
{
    int i;

#ifndef TEST
    int node_num= 0;
    server_info * pserverlist = NULL;

    RNLMUTEX_LOCK
    if(global_local_rn_list.global_rn_list.initialized){
        for(i=0;i<global_local_rn_list.global_rn_list.resolve_node_num;i++)
        {
            if(get_delay_parms(global_local_rn_list.global_rn_list.presolve_node[i].delaylevel)<=delayParameter)
                node_num++;
        }   

        if(isGlobalVisable&&global_local_rn_list.global_valid)
            node_num++;

        seaep_log("get_register_server_list num %d delayParameter %d\n",node_num,delayParameter);

        pserverlist = (server_info *)malloc(sizeof(server_info)*node_num); 
        memset(pserverlist,0,sizeof(server_info)*node_num);   
        *num = node_num;

        for(i=0;i<global_local_rn_list.global_rn_list.resolve_node_num;i++)
        {                
            if(get_delay_parms(global_local_rn_list.global_rn_list.presolve_node[i].delaylevel)<=delayParameter){
                strcpy(pserverlist[i].server_addr,global_local_rn_list.global_rn_list.presolve_node[i].na);
                pserverlist[i].port = SERVER_BASE_PORT+global_local_rn_list.global_rn_list.presolve_node[i].delaylevel;
            }
        }

        if(isGlobalVisable&&global_local_rn_list.global_valid)
        {
            //todo : add  a delay err record
            //if(node_num ==1)
                //;
            strcpy(pserverlist[node_num-1].server_addr,global_local_rn_list.global_resolve_addr);
            pserverlist[node_num-1].port = GLOBAL_RESOLVER_PORT;
        }
        
    }
    RNLMUTEX_UNLOCK
    return pserverlist;
#else
 server_info * pserverlist = (server_info *)malloc(sizeof(server_info)*(1));
 strcpy(pserverlist[0].server_addr,/*"192.168.189.202"*/TEST_RESOLVE_NODE_IP);
 pserverlist[0].port = RNL_PORT;
*num = 1;
 return pserverlist;

#endif
}
delay_item *get_delay_node(int *delay_num)
{
    *delay_num = 0;
    if(global_local_rn_list.global_rn_list.initialized &&global_local_rn_list.global_rn_list.pdelay_item!=NULL)
    {
        *delay_num = global_local_rn_list.global_rn_list.delaylevel_num;
        return global_local_rn_list.global_rn_list.pdelay_item;
    }
    return NULL;

}

child_node *get_child_node(int *child_num)
{
    *child_num = 0;
    if(global_local_rn_list.global_rn_list.initialized &&global_local_rn_list.global_rn_list.pchild_node !=NULL)
    {
        *child_num = global_local_rn_list.global_rn_list.child_node_num;
        return global_local_rn_list.global_rn_list.pchild_node;
    }
    return NULL;
}

resolve_node_inuse *get_resolve_node(int *resolve_num)
{
    *resolve_num = 0;
    if(global_local_rn_list.global_rn_list.initialized &&global_local_rn_list.global_rn_list.presolve_node!=NULL)
    {
        *resolve_num = global_local_rn_list.global_rn_list.resolve_node_num;
        return global_local_rn_list.global_rn_list.presolve_node;
    }
    return NULL;
}

neighbor_node *get_neighbor_node(int *neighbor_num)
{
    *neighbor_num = 0;
    if(global_local_rn_list.global_rn_list.initialized &&global_local_rn_list.global_rn_list.pneighbor_node!=NULL)
    {        
        *neighbor_num = global_local_rn_list.global_rn_list.neighbor_node_num;
        return &global_local_rn_list.global_rn_list.pneighbor_node[0];
    }
    return NULL;
}



void delete_register_server_list(server_info *serverlist, int num)
{
    if(!serverlist)
        return;

    free(serverlist);
    serverlist = NULL;
}

void delete_na_list(na_list_info *seaep_nalist)
{
    int i;
    if(!seaep_nalist)
        return;
    na_list_info * info = seaep_nalist;
    for(i=0;i<info->na_num;i++)
    {
        if(info->na_list[i]){
           free(info->na_list[i]);
           info->na_list[i]= NULL;
        }
     }
    if(info->na_list){
        free(info->na_list);
        info->na_list = NULL;
    }
    if(info){
        free(info);
        info = NULL;
    }

}


int update_resolver_list(rn_list *new_global_rn_list)
{
    free_resolver_list();
    RNLMUTEX_LOCK
    global_local_rn_list.global_rn_list.initialized = 1;
    memcpy(&global_local_rn_list.global_rn_list,new_global_rn_list,sizeof(rn_list));
    RNLMUTEX_UNLOCK

    return 0;
}

int update_global_resolve_addr(const char *global_addr)
{
    RNLMUTEX_LOCK
    global_local_rn_list.global_valid = 1;
    strncpy(global_local_rn_list.global_resolve_addr,global_addr,sizeof(global_local_rn_list.global_resolve_addr));
    RNLMUTEX_UNLOCK

    return 0;
}

const char* get_global_resolve_addr()
{
    return global_local_rn_list.global_resolve_addr;
}


