#ifndef MOBILE_APP_H
#define MOBILE_APP_H

#include <rte_ring.h>
#include "Defaults.h"
#include "init.h"
#include "seaep_loop.h"

#define NASTR_MAX_LEN 128
#define EID_LEN 20

/*
typedef struct {
    unsigned char na_num;
    char **na_list;
}na_list_info;


typedef struct node_list_info{
    char result;
    unsigned short local_port;
    char resolution_node_addr[NASTR_MAX_LEN];
} node_list_info;

typedef struct Result_info{
    unsigned char
type;//一般为SEAEP_ACTION_RESPONSE_RIGSTER、SEAEP_ACTION_RESPONSE_LOGOUT、
SEAEP_ACTION_RESPONSE_RESOLVE char finished; // 1为完成，0为超时退出 unsigned
char eid[20]; unsigned char node_num; node_list_info *node_info; na_list_info
*na_info; } Result_info;

typedef void * (*Result_func_cb)(void *context, Result_info *info);
*/
extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

// unsigned long int current_time_ms(void);

int mobile_process_loop(__attribute__((unused)) void *arg);

int addr_is_ipv4(char ip_addr[16]);
char *netbytes2ip(char *ip);
void ByteToHexStr(const unsigned char *source, unsigned char *dest,
                  int sourceLen);
void printfbuffer(unsigned char *buffer, int buffer_len);
void sendtotxt(unsigned char *buffer, int bufferlen, struct rte_ring *r);
void mob_mes_constructionandsending(void *message, unsigned char *newna,
                                    int fun_c);
void mob_resolveandsending(void *message, unsigned char *newna, int fun_c);

void *process_resolve_msg(void *metadata, Result_info *info);
void print_eid(char eid[EID_LEN]);
// int process_register_msg(void *context, Result_info *info);
// int process_resolve_msg(void *context, Result_info *info);
// int process_unregister_msg(void *context, Result_info *info);

#endif /* MOBILE_APP_H */

/*
#ifndef MOBILE_APP_H
#define MOBILE_APP_H
 

#include "Defaults.h"
#include "init.h"

extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];
 

 

 

int mobile_process_loop(__attribute__((unused)) void *arg);
 

 

#endif
*/
