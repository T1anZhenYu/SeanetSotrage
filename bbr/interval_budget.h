/*-
* Copyright (c) 2017-2018 wenba, Inc.
*	All rights reserved.
*
* See the file LICENSE for redistribution information.
*/

#ifndef __interval_hudget_h_
#define __interval_hudget_h_

#include "common/cf_platform.h"
#include <stdint.h>

/*��λʱ���ڵķ����ֽڹ���*/
typedef struct
{
	int target_rate_kbps;
	int max_bytes_in_budget;
	int bytes_remaining;
	int can_build_up_underuse;
}interval_budget_t;

void			init_interval_budget(interval_budget_t* budget, int initial_target_rate_kbps, int can_build_up_underuse);
void			set_target_rate_kbps(interval_budget_t* budget, int target_rate_kbps);

/*����ʱ����*/
void			increase_budget(interval_budget_t* budget, int delta_ts);
/*���������ݣ�����budget�ֽڼ���*/
void			use_budget(interval_budget_t* budget, int bytes);

int				budget_level_precent(interval_budget_t* budget);

size_t			budget_remaining(interval_budget_t* budget);


#endif



