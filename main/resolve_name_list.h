#ifndef RESOLVE_NAME_LIST_H
#define RESOLVE_NAME_LIST_H

#define SERVER_BASE_PORT 10060
#define GLOBAL_RESOLVER_PORT 10090

/*
*
*/
typedef struct{
    char server_addr[128];
    int port;
    int result;
}server_info;


typedef struct {
    unsigned char delaylevel;
    unsigned char delay_parms;
}delay_item;

typedef struct {
    unsigned char delaylevel;
    char id[4];
    char na[128];
}resolve_node_inuse;

typedef struct {
    char id[4];
    char na[128];
}neighbor_node;

typedef struct {
    int delaylevel;
    char id[4];
    char na[128];
}child_node;


typedef struct {
    unsigned char na_num;
    char **na_list;
}na_list_info;


typedef struct
{
    int is_ipv4;
    int initialized;
    unsigned char delaylevel_num;
    delay_item *pdelay_item;
    unsigned char resolve_node_num;
    resolve_node_inuse *presolve_node;
    unsigned char neighbor_node_num;
    neighbor_node *pneighbor_node;
    unsigned char child_node_num;
    child_node *pchild_node;

}rn_list;

rn_list *get_rn_list(void);

int renew_rn_list(void);

int update_resolver_list(rn_list *new_global_rn_list);

int get_delay_level(int delayparms);

int initialize_rnl_list(rn_list *prn_list);

int print_resolver_list(void);

int free_resolver_list(void);

server_info *get_register_server_list_lowlevel(int *num, int isGlobalVisable,int delayParameter);

server_info *get_register_server_list(int *num, int isGlobalVisable,int delayParameter);

void delete_register_server_list(server_info *serverlist, int num);

void delete_na_list(na_list_info *seaep_nalist);

delay_item *get_delay_node(int *delay_num);
child_node *get_child_node(int *child_num);

resolve_node_inuse *get_resolve_node(int *resolve_num);

neighbor_node *get_neighbor_node(int *neighbor_num);

int update_global_resolve_addr(const char *global_addr);

const char* get_global_resolve_addr(void);
int get_delay_parms(int level);
#endif
