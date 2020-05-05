/*
Author: YH Li
Build a dedicated lcore to implement file system IO operation
*/
#ifndef _WRITER_CORE_H_
#define _WRITER_CORE_H_

#include "Defaults.h"
#include "cs_two.h"
#include "init.h"

#define PRIMARY_FOLDER_NUM \
  128 /*the root directory of our file system has 128 primary folders*/
#define SECONDARY_FOLDER_NUM \
  128 /*every primary folder contains 128 secondary folders*/

extern struct app_global_config app_conf;
extern struct app_lcore_params lcore_conf[APP_MAX_LCORES];

int fs_io_loop(__attribute__((unused)) void *arg);

#endif /*_WRITER_CORE_H_ */
