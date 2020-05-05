#ifndef _TX_ACTION_H_
#define _TX_ACTION_H_

#include "Defaults.h"
#include "cs_two.h"
#include "init.h"
#include "seanet_packet.h"
#include "util.h"

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

int tx_process_loop(__attribute__((unused)) void *arg);

#endif /* _TX_ACTION_H_ */