/*-
* Copyright (c) 2017-2018 wenba, Inc.
*	All rights reserved.
*
* See the file LICENSE for redistribution information.
*/

#ifndef __cf_unwrapper_h_
#define __cf_unwrapper_h_

#include <stdint.h>

/*һ��ѭ�����������У�����һ��uint16_t���͵�seq,����65535��ͻص�0�ˣ�������ṹ���Ա�ʾ��Զ�ĵ���*/

typedef struct
{
	int		size;
	int64_t last_value;		/*���͵�ǰֵ*/
}cf_unwrapper_t;

void		init_unwrapper16(cf_unwrapper_t* wrap);
int64_t		wrap_uint16(cf_unwrapper_t* wrap, uint16_t val);

void		init_unwrapper32(cf_unwrapper_t* wrap);
int64_t		wrap_uint32(cf_unwrapper_t* wrap, uint32_t val);

#endif
