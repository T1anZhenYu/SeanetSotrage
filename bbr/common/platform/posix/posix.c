#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "../../cf_platform.h"



int64_t su_get_sys_time()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec + (int64_t)tv.tv_sec * 1000 * 1000;
}



