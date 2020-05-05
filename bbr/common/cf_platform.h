/*-
* Copyright (c) 2017-2018 wenba, Inc.
*	All rights reserved.
*
* See the file LICENSE for redistribution information.
*/

#ifndef _CF_PLATFORM_H
#define _CF_PLATFORM_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef WIN32
#include <windows.h>

#pragma warning(disable: 4996) //this is about sprintf, snprintf, vsnprintf

#define snprintf _snprintf

#ifndef inline
#define	inline __inline
#endif

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


#define IP_SIZE 32

#define SU_MAX(a, b)		((a) > (b) ? (a) : (b))
#define SU_MIN(a, b)		((a) < (b) ? (a) : (b))	
#define SU_ABS(a, b)		((a) > (b) ? ((a) - (b)) : ((b) - (a)))

#define GET_SYS_MS()		(su_get_sys_time() / 1000)

#ifdef __cplusplus
}
#endif

#endif
