#ifndef _DISPATCH_CORE_H_
#define _DISPATCH_CORE_H_

/**
 *  * @file
 *   *
 *     */

#include <rte_ip.h>
#include <stdint.h>
#include "Defaults.h"
#include "init.h"
#include "seanet_packet.h"

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

int64_t dispatch_packet(struct rte_mbuf *m_packet, struct app_global_config *app,
                       struct app_lcore_params *conf,
                     unsigned lcore_id, unsigned socket_id, uint8_t port_id);
void dispatch_recovery_packet(char *eid, struct app_lcore_params *conf,struct app_global_config *app);
int dispatch_loop(__attribute__((unused)) void *arg);

#endif /* _DISPATCH_CORE_H_ */
