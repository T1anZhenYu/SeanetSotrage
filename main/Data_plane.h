#ifndef _DATA_PLANE_H_
#define _DATA_PLANE_H_

/**
 * @file
 *
 * Data plane implementation
 */

#include "Defaults.h"
#include "cs_two.h"
#include "init.h"
#include "seanet_packet.h"

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

/**
 * Reset the statistics
 */
void reset_stats(void);

/**
 * Print all statistics on screen
 */
void print_stats(void);

int seanet_packet_process_loop(__attribute__((unused)) void *arg);

#endif /* _DATA_PLANE_H_ */
