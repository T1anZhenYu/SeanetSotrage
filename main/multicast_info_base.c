// multicast_info_base

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "multicast_ae.h"
#include "mobile_app.h"
#include "seaep_loop.h"
#include "init.h"

uint8_t multi_ser_test[20] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0};
uint8_t ip_test[16] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};
//uint16_t outport_test[PORTNUM] = {5000};
int target_null = -1;
uint8_t mac_addr_test[6] = {1,2,3,4,5,222};

int info_base_init()
{
	edge_switch_info_base.server_num =  0;
	forward_info_base.forward_num = 0;
	forward_info_base.forward_info = NULL;
	edge_switch_info_base.edge_switch_info = NULL;
	return AE_OK;
}

bool host_info_base_is_empty()
{
	if (edge_switch_info_base.server_num  == 0)
		return true;
	return false;
}

int* search_multicast_forward_info(uint8_t* multicast_service_eid, uint8_t* pre_ip, uint16_t inport, uint16_t outport)
{
	static int res[2] = {-1,-1};
	res[0] = -1;
	res[1] = -1;
	//printf("debug -1- %d, %d, %d\n", forward_num, res[0], res[1]);
	if (forward_info_base.forward_num == 0)
		return res;
	int i = 0;
	FORWARD_INFO* temp = forward_info_base.forward_info;
	while (temp != NULL)
	{
		if ((temp->inport == inport) && (memcmp(multicast_service_eid, temp->multicast_service_eid, MSLEN) == 0) 
		&& (memcmp(pre_ip, temp->pre_ip, IP6LEN) == 0))
		{
			res[0] = i;
			int j = 0;
			for (; j < temp->outport.outport_num; ++j)
			{
				if (outport == temp->outport.outport_index[j])
				{
					res[1] = j;
					return res;
				}
			}
		}
		else
		{
			temp = temp->next;
			i++;
		}
	}
	return res;
}

void add_multicast_forward_info(uint8_t* multicast_service_eid, uint8_t* pre_ip, uint16_t inport, uint16_t outport)
{
	//printf("\ndebug -2- %02X\n", outport);
	int* index = search_multicast_forward_info(multicast_service_eid, pre_ip, inport, outport);
	if (index[0] != -1 && index[1] != -1)
	{
		printf("Table 1 : Already exist! Can not add the same entry!\n");
		return;
	}
	if (index[0] == -1)
	{
		printf("Table 1 : Did not have this EID. Adding it now~\n");
		uint32_t forward_number = forward_info_base.forward_num;
		if (forward_number < FORWARDNUM - 1)
		{
			FORWARD_INFO* node = NULL;
			node = calloc(1, sizeof(FORWARD_INFO));
			if (NULL == node) {
				printf("ERROR: calloc memory fail.\n");
				return;
			} 
			node->inport = (inport);
			node->outport.outport_index[0] = outport;
			node->outport.outport_num = 1;
			node->next = NULL;
			memcpy(node->multicast_service_eid, multicast_service_eid, MSLEN);
			memcpy(node->pre_ip, pre_ip, IP6LEN);
			FORWARD_INFO* temp = forward_info_base.forward_info;
			if (temp == NULL)
			{
				forward_info_base.forward_info = node;
				forward_info_base.forward_num = 1;
				return;
			}
			while (temp->next != NULL)
			{
				temp = temp->next;
			}
			temp->next = node;
			forward_info_base.forward_num++;
		}
		else
		{
			printf("Table 1 : Forwarding table is full! Can not add a new entry!\n");
		}
	}
	else if (index[0] != -1 && index[1] == -1)
	{
		printf("Table 1 : Already have this EID. Did not have this OUTPORT. Adding it now~\n");
		int i = index[0];
		FORWARD_INFO* temp = forward_info_base.forward_info;
		int m = 0;
		for (; m < i; ++m)
		{
			if (temp != NULL)
			{
				temp = temp->next;
			}
			else
			{
				printf("Tabel 1 : Add entry error!\n");
				return;
			}
		}
		int num_temp = temp->outport.outport_num;
		if (num_temp < PORTNUM - 1)
		{
			temp->outport.outport_index[num_temp] = outport;
			temp->outport.outport_num++;
		}
		else
		{
			printf("Table 1 : Forwarding table's ports are full! Can not add a new entry!\n");
		}
	}
	else
	{
		printf("Tabel 1 : Add entry error!\n");
	}
}

int delete_multicast_forward_info(uint8_t* multicast_service_eid, uint8_t* pre_ip, uint16_t inport, uint16_t outport)
{
	printf("\ndebug -3-\n");
	FORWARD_INFO* temp_head = forward_info_base.forward_info;
	if (forward_info_base.forward_num > 0)
	{
		printf("delete_multicast_forward_info tag 1\n");
		int* index = search_multicast_forward_info(multicast_service_eid, pre_ip, inport, outport);
		printf("delete_multicast_forward_info tag 2\n");
		int i = index[0];
		int j = index[1];
		if (index[0] == -1 || index[1] == -1)
		{
			printf("delete_multicast_forward_info tag 3\n");
			printf("Table 1 : Forwarding table does not have this entry! Can not delete it!\n");
			return AE_ERROR;
		}
		else
		{
			printf("i = %d, j = %d\n", i, j);
			int m = 0;
			for (; m < i; ++m)
			{
				if (temp_head != NULL)
				{
					temp_head = temp_head->next;
				}
				else
				{
					printf("Tabel 1 : Add entry error!\n");
					return AE_ERROR;
				}
			}
			uint32_t temp = temp_head->outport.outport_num;
			printf("delete_multicast_forward_info tag 4\n");
			for (; j < temp - 1; ++j)
			{
				temp_head->outport.outport_index[j] = temp_head->outport.outport_index[j + 1];
			}
			printf("delete_multicast_forward_info tag 5\n");
			temp_head->outport.outport_num--;
		}
		if (temp_head->outport.outport_num == 0)
		{
			FORWARD_INFO* pre = NULL;
			FORWARD_INFO* node = forward_info_base.forward_info;
			while (node != temp_head)
			{
				pre = node;
				node = node->next;
			}
			if (pre != NULL)
				pre->next = temp_head->next;
			else
				forward_info_base.forward_info = forward_info_base.forward_info->next;
			free(temp_head);
			temp_head = NULL;
			forward_info_base.forward_num--;
			return AE_OK;
		}
	}
	else
	{
		printf("Table 1 : Forwarding table is empty! Can not delete an entry!\n");
		return AE_ERROR;
	}
	return AE_ERROR;
}

int delete_multicast_forward_info_v2(uint8_t* multicast_service_eid, uint8_t* pre_ip, uint16_t inport, uint16_t outport)
{
	//printf("delete vision-2\n");
	FORWARD_INFO* temp_head = forward_info_base.forward_info;
	if (forward_info_base.forward_num > 0)
	{
		int* index = search_multicast_forward_info(multicast_service_eid, pre_ip, inport, outport);
		int i = index[0];
		int j = index[1];
		if (index[0] == -1 || index[1] == -1)
		{
			printf("Table 1 : Forwarding table does not have this entry! Can not delete it!\n");
			return AE_ERROR;
		}
		else
		{
			int m = 0;
			for (; m < i; ++m)
			{
				if (temp_head != NULL)
				{
					temp_head = temp_head->next;
				}
				else
				{
					printf("Tabel 1 : Add entry error!\n");
					return AE_ERROR;
				}
			}
			uint32_t temp = temp_head->outport.outport_num;
			for (; j < temp - 1; ++j)
			{
				temp_head->outport.outport_index[j] = temp_head->outport.outport_index[j + 1];
			}
			temp_head->outport.outport_num--;
			return AE_OK;
		}
	}
	else
	{
		printf("Table 1 : Forwarding table is empty! Can not delete an entry!\n");
		return AE_ERROR;
	}
}

int delete_multicast_forward_info_v3(uint8_t* multicast_service_eid)
{
	if (forward_info_base.forward_num > 0)
	{
		FORWARD_INFO* pre = NULL;
		FORWARD_INFO* node = forward_info_base.forward_info;
		if (node == NULL)
		{
			printf("Table 1 : Forwarding table is empty! Can not delete an entry!\n");
			return AE_ERROR;
		}
		FORWARD_INFO* next = forward_info_base.forward_info->next;
		while (node != NULL)
		{
			next = node->next;
			if (memcmp(multicast_service_eid, node->multicast_service_eid, MSLEN) == 0)
			{
				if (pre == NULL)
				{
					forward_info_base.forward_info = next;
				}
				else
				{
					pre->next = next;
				}
				free(node);
				node = NULL;
				printf("Table 1 : Deleted a multicast service!\n");
				return AE_OK;
			}
			pre = node;
			node = next;
		}
	}
	else
	{
		printf("Table 1 : Forwarding table is empty! Can not delete an entry!\n");
		return AE_ERROR;
	}
	printf("Table 1 : Delete error!\n");
	return AE_ERROR;
}

/*void revise_multicast_forward_info(int i, int j, uint8_t* multicast_service_eid, uint8_t* pre_ip, uint16_t inport, uint16_t outport)
{
	if (i < 0 || i >= forward_info_base.forward_num || j < 0 || j >= forward_info_base.forward_info_[i].outport.outport_num)
	{
		printf("Table 1 : Forwarding table does not have this entry! Can not revise it!\n");
	}
	else
	{
		forward_info_base.forward_info_[i].inport = inport;
		memcpy(forward_info_base.forward_info_[i].multicast_service_eid, multicast_service_eid, MSLEN);
		memcpy(forward_info_base.forward_info_[i].pre_ip, pre_ip, IP6LEN);
		forward_info_base.forward_info_[i].outport.outport_index[j] = outport;
	}
}*/

int* search_host_info(uint8_t* multicast_service_eid, uint16_t port, uint8_t* mac_addr, uint8_t* host_ip)
{
	static int res[3] = {-1,-1,-1};
	res[0] = -1;
	res[1] = -1;
	res[2] = -1;
	int i = 0;
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	if (head == NULL)
	{
		return res;
	}
	while (head != NULL)
	{
		if (memcmp(head->multicast_service_eid, multicast_service_eid, MSLEN) == 0)
		{
			if (head->ports_num == 0)
			{
				return res;
			}
			res[0] = i;
			int j = 0;
			for (; j < head->ports_num; ++j)
			{
				if (port == head->ports[j].port)
				{
					if (head->ports[j].hosts_num == 0)
					{
						return res;
					}
					res[1] = j;
					int k = 0;
					for (; k < head->ports[j].hosts_num; ++k)
					{
						if (memcmp(head->ports[j].hosts[k].host_ip, host_ip, IP6LEN) == 0
						&& memcmp(head->ports[j].hosts[k].mac_addr, mac_addr, MACLEN) == 0)
						{
							res[2] = k;
							return res;
						}
					}
				}
			}
		}
		i++;
		head = head->next;
	}
	return res;
}

void add_host_info(uint8_t* multicast_service_eid, uint16_t port, uint8_t* mac_addr, uint8_t* host_ip)
{
	/*int tmp = 0;
	for (; tmp < MACLEN; ++tmp)
	{
		printf("MACADDR = %d\n", mac_addr[tmp]);
	}*/
	int* index = search_host_info(multicast_service_eid,port,mac_addr,host_ip);
	int i = index[0];
	int j = index[1];
	int k = index[2];
	if (i != -1 && j != -1 && k != -1)
	{
		printf("Table 2 : Already exist! Can not add the same entry!\n");
		return;
	}
	if (i == -1)
	{
		printf("Table 2 : Did not have this EID. Adding it now~\n");
		if (edge_switch_info_base.server_num < SERVERNUM - 1)
		{
			EDGE_SWITCH_INFO* node = NULL;
			node = calloc(1, sizeof(EDGE_SWITCH_INFO));
			if (NULL == node) {
				printf("ERROR: calloc memory fail.\n");
				return;
			} 
			node->next = NULL;
			node->ports_num = 1;
			node->ports[0].port = port;
			node->ports[0].hosts_num = 1;
			node->ports[0].hosts[0].count = 0;
			memcpy(node->multicast_service_eid, multicast_service_eid, MSLEN);
			memcpy(node->ports[0].hosts[0].host_ip, host_ip, IP6LEN);
			memcpy(node->ports[0].hosts[0].mac_addr, mac_addr, MACLEN);
			EDGE_SWITCH_INFO* temp = edge_switch_info_base.edge_switch_info;
			//printf("hello there - 1 -\n");
			if (temp == NULL)
			{
				//printf("hello there - 2 -\n");
				edge_switch_info_base.edge_switch_info = node;
				//printf("%d\n", node->ports_num);
				//printf("%d\n", edge_switch_info_base.edge_switch_info->ports_num);
				edge_switch_info_base.server_num = 1;
				return;
			}
			while (temp->next != NULL)
			{
				temp = temp->next;
			}
			temp->next = node;
			edge_switch_info_base.server_num ++;
		}
		else
		{
			printf("Table 2 : Hosts table's sevice is full! Can not add a new entry!\n");
			return;
		}
	}
	else if (i != -1 && j == -1 && k == -1)
	{
		printf("Table 2 : Already have this EID. Did not have this OUTPORT. Adding it now~\n");
		EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
		int i_temp = 0;
		for (; i_temp < i; ++i_temp)
		{
			if (head == NULL)
			{
				printf("Table 2 : Add Error!\n");
				return;
			}
			head = head->next;
		}
		if (head->ports_num < PORTNUM - 1)
		{
			uint32_t temp = head->ports_num;
			head->ports[temp].port = (port);
			head->ports[temp].hosts_num = 1;
			head->ports[temp].hosts[0].count = 0;
			memcpy(head->ports[temp].hosts[0].mac_addr, mac_addr, MACLEN);
			memcpy(head->ports[temp].hosts[0].host_ip, host_ip, IP6LEN);
			head->ports_num = temp + 1;
		}
		else
		{
			printf("Table 2 : This sevice's ports are full! Can not add a new entry!\n");
		}
	}
	else if (i != -1 && j != -1 && k == -1)
	{
		printf("Table 2 : Already have this EID and this OUTPORT. Did not have this HOST. Adding it now~\n");
		EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
		int i_temp = 0;
		for (; i_temp < i; ++i_temp)
		{
			if (head == NULL)
			{
				printf("Table 2 : Add Error!\n");
				return;
			}
			head = head->next;
		}
		if (head->ports[j].hosts_num < HOSTNUM - 1)
		{
			uint32_t temp = head->ports[j].hosts_num;
			head->ports[j].hosts[temp].count = 0;
			memcpy(head->ports[j].hosts[temp].host_ip, host_ip, IP6LEN);
			memcpy(head->ports[j].hosts[temp].mac_addr, mac_addr, MACLEN);
			head->ports[j].hosts_num = temp + 1;
		}
		else
		{
			printf("Table 2 : This port's hosts are full! Can not add a new entry!\n");
		}
	}
	else
	{
		printf("Tabel 2 : Add entry error.\n");
	}
}

void delete_host_info(uint8_t* multicast_service_eid, uint16_t port, uint8_t* mac_addr, uint8_t* host_ip)
{
	if (edge_switch_info_base.server_num == 0)
	{
		printf("Table 2 : Hosts table is empty! Can not delete an entry!\n");
		return;
	}
	int* index = search_host_info(multicast_service_eid, port, mac_addr, host_ip);
	if (index[0] != -1 && index[1] != -1 && index[2] != -1)
	{
		int i = index[0];
		int j = index[1];
		int k = index[2];
		EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
		EDGE_SWITCH_INFO* pre = NULL;
		int i_temp = 0;
		for (; i_temp < i; ++i_temp)
		{
			if (head == NULL)
			{
				printf("Table 2 : Delete Error!\n");
				return;
			}
			pre = head;
			head = head->next;
		}
		uint32_t temp1 = head->ports[j].hosts_num;
		for (; k < temp1 - 1; ++k)
		{
			head->ports[j].hosts[k] =head->ports[j].hosts[k + 1];
		}
		head->ports[j].hosts_num = temp1 - 1;
		if (head->ports[j].hosts_num == 0)
		{
			uint32_t temp2 = head->ports_num;
			for (; j < temp2 - 1; ++j)
			{
				head->ports[j] = head->ports[j + 1];
			}
			head->ports_num = temp2 - 1;
			if (head->ports_num == 0)
			{
				EDGE_SWITCH_INFO* next = head->next;
				if (pre == NULL)
				{
					edge_switch_info_base.edge_switch_info = next;
					free(head);
					head = NULL;
				}
				else
				{
					pre->next = next;
					free(head);
					head = NULL;
				}
				edge_switch_info_base.server_num--;
			}
		}
	}
	else
	{
		printf("Table 2 : Hosts table does not have this entry! Can not delete it!\n");
	}
	
}

void delete_host_info_v2(EDGE_SWITCH_INFO *edge_switch, PORT_INFO *port)//delete a port
{
	if (edge_switch_info_base.server_num == 0)
	{
		printf("Table 2 : Hosts table is empty! Can not delete an entry!\n");
		return;
	}
	int i = 0;
	for (; i < edge_switch->ports_num; ++i)
	{
		if (edge_switch->ports[i].port == port->port)/* TODO redefine ' PORT_INFO equals to PORT_INFO'*/
		{
			int j = i;
			for (; j < edge_switch->ports_num - 1; ++j)
			{
				edge_switch->ports[j] = edge_switch->ports[j + 1];
			}
			edge_switch->ports_num--;
			return;
		}
	}
}

void delete_host_info_v3(uint8_t* multicast_service_eid)//delete a kind of multicast server
{
	if (edge_switch_info_base.server_num == 0)
	{
		printf("Table 2 : Hosts table is empty! Can not delete an entry!\n");
		return;
	}
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	EDGE_SWITCH_INFO* pre = NULL;
	EDGE_SWITCH_INFO* next = head->next;
	while (head != NULL)
	{
		next = head->next;
		if (memcmp(head->multicast_service_eid, multicast_service_eid, MSLEN) == 0)
		{
			if (pre == NULL)
			{
				edge_switch_info_base.edge_switch_info = next;
				free(head);
				head = NULL;
			}
			else
			{
				pre->next = next;
				free(head);
				head = NULL;
			}
			printf("Table 2 : Deleted a multicast service!!\n");
			break;
		}
		//printf("delete 3 tag here -1- \n");
		pre = head;
		head = next;
		//printf("delete 3 tag here -2- \n");
	}
}

void delete_host_info_v4(PORT_INFO *port, HOST_INFO *host)//delete a host
{
	//printf("Get in delete-v4\n");
	if (edge_switch_info_base.server_num == 0)
	{
		printf("Table 2 : Hosts table is empty! Can not delete a host!\n");
		return;
	}

	int i = 0;
	for (; i < port->hosts_num; ++i)
	{
		//printf("delete-v4 tag -1- \n");
		if (memcmp(host->host_ip, port->hosts[i].host_ip, IP6LEN) == 0
		&& memcmp(host->mac_addr, port->hosts[i].mac_addr, MACLEN) == 0)/* TODO redefine ' HOST_INFO equals to HOST_INFO'*/
		{
			//printf("delete-v4 tag -2- \n");
			if (i == port->hosts_num - 1)
			{
				//printf("delete-v4 tag -3- \n");
				port->hosts_num--;
				return;
			}
			int j = i;
			for (; j < port->hosts_num - 1; ++j)
			{
				//printf("delete-v4 tag -4- \n");
				port->hosts[j] = port->hosts[j + 1];
			}
			port->hosts_num--;
			return;
		}
	}
}

/*void revise_host_info(int i, int j, int k, uint8_t* multicast_service_eid, uint16_t port, uint8_t* mac_addr, uint8_t* host_ip)
{
	if ((i < 0 || i >= edge_switch_info_base.server_num)
	 || (j < 0 || j >= edge_switch_info_base.edge_switch_info_[i].ports_num)
	 || (k < 0 || k >= edge_switch_info_base.edge_switch_info_[i].ports[j].hosts_num))
	{
		printf("Table 2 : Hosts table does not have this entry! Can not revise it!\n");
	}
	else
	{
		memcpy(edge_switch_info_base.edge_switch_info_[i].ports[j].hosts[k].host_ip, host_ip, IP6LEN);
		memcpy(edge_switch_info_base.edge_switch_info_[i].ports[j].hosts[k].mac_addr, mac_addr, MACLEN);
	}
}*/

/*add new APIs 2019/10/29*/

BOOL is_multicast_in_forward_info_base(uint8_t *multicast_service_eid)
{
	//forward_info_base
	FORWARD_INFO* head = forward_info_base.forward_info;
	if (head == NULL)
	{
		//printf("is_multicast_in_forward_info_base---1---\n");
		return false;
	}
	while (head != NULL)
	{
		//printf("is_multicast_in_forward_info_base---2---\n");
		int i = 0;
		printf("new eid = ");
		for (; i < MSLEN; ++i)
		{
			printf("%d ", multicast_service_eid[i]);
		}
		i = 0;
		printf("\nold eid = ");
		for (; i < MSLEN; ++i)
		{
			printf("%d ", head->multicast_service_eid[i]);
		}
		printf("\n");
		if (memcmp(multicast_service_eid, head->multicast_service_eid, MSLEN) == 0)
		{
			return true;
		}
		head = head->next;
	}
	return false;
}
//function-1

FORWARD_INFO* get_forward_info_from_forward_info_base(uint8_t *multicast_service_eid)
{
	FORWARD_INFO* head = forward_info_base.forward_info;
	if (head == NULL)
	{
		return NULL;
	}
	while (head != NULL)
	{
		if (memcmp(multicast_service_eid, head->multicast_service_eid, MSLEN) == 0)
		{
			printf("GOT THE EID~\n");
			return head;
		}
		head = head->next;
	}
	return NULL;
}
//function-4

uint16_t* get_outports_from_forward_info_base(uint8_t *multicast_service_eid, uint16_t *port_num)
{
	FORWARD_INFO* head = forward_info_base.forward_info;
	if (head == NULL)
	{
		return NULL;
	}
	while (head != NULL)
	{
		if (memcmp(multicast_service_eid, head->multicast_service_eid, MSLEN) == 0)
		{
			(*port_num) = head->outport.outport_num;
			printf("GOT OUT_PORTS~\n");
			return head->outport.outport_index;
		}
		head = head->next;
	}
	return NULL;
}
//function-2

uint16_t * get_outports_from_forward_info(FORWARD_INFO *fwd_info, uint16_t *port_num)
{
	(*port_num) = fwd_info->outport.outport_num;
	return (fwd_info->outport.outport_index);
}
//function-3

int forward_info_base_add_multicast(uint8_t *multicast_service_eid, uint8_t *pre_ip, uint16_t inport, uint16_t outport)
{
	add_multicast_forward_info(multicast_service_eid, pre_ip, inport, outport);
	return 0;
}
//function-5

int forward_info_base_delete_multicast(uint8_t *multicast_service_eid)
{
	return delete_multicast_forward_info_v3(multicast_service_eid);
	//return 0;
}
//function-6

int forward_info_delete_outport(FORWARD_INFO *fwd_info, uint16_t port)
{
	// delete_multicast_forward_info_v2(fwd_info->multicast_service_eid, fwd_info->pre_ip, fwd_info->inport, port);
	// printf("*********************tag1*****************************\n");
	// printf("%s\n", );
	int i = 0;
	for (; i < fwd_info->outport.outport_num; ++i)
	{
		//printf("*********************tag2*****************************\n");
		printf("pkt's port = %02X, fwd base's outport = %02X\n", port, fwd_info->outport.outport_index[i]);	
		if (fwd_info->outport.outport_index[i] == port)
		{
			//printf("*********************tag3*****************************\n");
			int j = i;
			for (; j < fwd_info->outport.outport_num - 1; ++j)
			{
				fwd_info->outport.outport_index[j] = fwd_info->outport.outport_index[j + 1];
			}
			fwd_info->outport.outport_num--;
			printf("outport_num after deleting = %d\n", fwd_info->outport.outport_num);
			return AE_OK;
		}
	}
	return AE_ERROR;
}
//function-7

int forward_info_add_outport(FORWARD_INFO *fwd_info, uint16_t outport)
{
	//add_multicast_forward_info(fwd_info->multicast_service_eid, fwd_info->pre_ip, fwd_info->inport, outport);
	// printf("Table 1 : Already have this EID. Did not have this OUTPORT. Adding it now~\n");
	int i = 0;
	for (; i < fwd_info->outport.outport_num; ++i)
	{
		if (fwd_info->outport.outport_index[i] == outport)
		{
			printf("Table 1 : Already have this EID and this OUTPORT. Exit now~\n");
			return AE_OK;
		}
	}
	if (fwd_info->outport.outport_num < PORTNUM - 1)
	{
		fwd_info->outport.outport_index[fwd_info->outport.outport_num] = outport;
		fwd_info->outport.outport_num++;
		printf("Table 1 : Already have this EID. Did not have this OUTPORT. Adding it now~\n");
		return AE_OK;
	}
	return AE_ERROR;
}
//function-8

/* part 1 is finished, part 2 to begin */
int host_info_base_delete_multicast(uint8_t *multicast_service_eid)
{
	delete_host_info_v3(multicast_service_eid);
	return 0;
}
//function-15

int host_info_base_add_host(uint8_t *multicast_service_eid, uint16_t port, uint8_t *mac, uint8_t *ip)
{
	add_host_info(multicast_service_eid,port, mac, ip);
	//printf("double check for edge_switch_info->ports_num = %d\n", edge_switch_info_base.edge_switch_info->ports_num);
	return 0;
}
//function-16

EDGE_SWITCH_INFO* get_edge_switch_info_from_host_info_base(uint8_t *multicast_service_eid)
{
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	if (head == NULL)
	{
		return NULL;
	}
	while (head != NULL)
	{
		if (memcmp(multicast_service_eid, head->multicast_service_eid, MSLEN) == 0)
		{
			return head;
		}
		head = head->next;
	}
	return NULL;
}
//function-17

HOST_INFO* get_host_info_from_host_info_base(uint8_t *multicast_service_eid, uint8_t *mac, uint8_t *ip)
{
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	if (head == NULL)
	{
		return NULL;
	}
	while (head != NULL)
	{
		if (memcmp(multicast_service_eid, head->multicast_service_eid, MSLEN) == 0)
		{
			int i = 0;
			for (; i < head->ports_num; ++i)
			{
				int j = 0;
				for (; j < head->ports[i].hosts_num; ++j)
				{
					if (memcmp(mac, head->ports[i].hosts[j].mac_addr, MACLEN) == 0 
					&& memcmp(ip, head->ports[i].hosts[j].host_ip, IP6LEN) == 0)
					{
						return &(head->ports[i].hosts[j]);
					}
				}
			}
		}
		head = head->next;
	}

	return NULL;
}
//function-14

HOST_INFO* get_host_info_from_edge_switch_info(EDGE_SWITCH_INFO *edge_switch_info, uint8_t *mac, uint8_t *ip)
//HOST_INFO* get_host_from_edge_switch_info(EDGE_SWITCH_INFO *edge_switch_info, uint8_t *mac, uint8_t *ip)
{
	//printf("get in function-13, ports_num = %d\n", edge_switch_info->ports_num);
	int i = 0;
	printf("The IPv6 Addr which need to be matched is : ");
	for (; i < IP6LEN; ++i)
	{
		printf("%x ", ip[i]);
	}
	printf("\n");
	i = 0;
	printf("The MAC which need to be matched is : ");
	for (; i < MACLEN; ++i)
	{
		printf("%x ", mac[i]);
	}
	printf("\n");
	printf("Ports' num = %x \n", edge_switch_info->ports_num);
	int j = 0;
	for (; j < edge_switch_info->ports_num; ++j)
	{
		printf("Port's index = %x\n", edge_switch_info->ports[j].port);
		printf("Hosts' num = %d\n", edge_switch_info->ports[j].hosts_num);
		int k = 0;
		for (; k < edge_switch_info->ports[j].hosts_num; ++k)
		{
			printf("Host's MAC = ");
			i = 0;
			for (; i < MACLEN; ++i)
			{
				printf("%x ", edge_switch_info->ports[j].hosts[k].mac_addr[i]);
			}
			printf("\n");
			printf("Host's IP = ");
			i = 0;
			for (; i < IP6LEN; ++i)
			{
				printf("%x ", edge_switch_info->ports[j].hosts[k].host_ip[i]);
			}
			printf("\n");
			if (memcmp(edge_switch_info->ports[j].hosts[k].mac_addr, mac, MACLEN) == 0
			&& memcmp(edge_switch_info->ports[j].hosts[k].host_ip, ip, IP6LEN) == 0)
			{
				printf("GOT THE HOST!\n");
				//printf("%p\n", &(edge_switch_info->ports[j].hosts[k]));
				return &(edge_switch_info->ports[j].hosts[k]);
			}
		}
	}
	return NULL;
}
//function-13

PORT_INFO* get_port_info_from_edge_switch_info(EDGE_SWITCH_INFO *edge_switch, HOST_INFO *host)
{
	int j = 0;
	for (; j < edge_switch->ports_num; ++j)
	{
		int k = 0;
		for (; k < edge_switch->ports[j].hosts_num; ++k)
		{
			if (memcmp(edge_switch->ports[j].hosts[k].host_ip, host->host_ip, IP6LEN) == 0
			&& memcmp(edge_switch->ports[j].hosts[k].mac_addr, host->mac_addr, MACLEN) == 0)
			{
				printf("GOT THE PORT!\n");
				return &(edge_switch->ports[j]);
			}
		}
	}
	return NULL;
}
//function-12

int edge_switch_info_delete_port(EDGE_SWITCH_INFO *edge_switch, PORT_INFO *port)
{
	delete_host_info_v2(edge_switch, port);
	return 0;
}
//function-11

int port_info_delete_host(PORT_INFO *port, HOST_INFO *host)
{
	delete_host_info_v4(port, host);
	return 0;
}
//function-10

int host_info_clear_counter(HOST_INFO* host)
{
	host->count = 0;
	return 0;
}
//function-9

int get_outport_num_from_host_info_base(uint8_t *eid)
{
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	if (head == NULL)
	{
		return AE_ERROR;
	}
	while (head != NULL)
	{
		if (memcmp(eid, head->multicast_service_eid, MSLEN) == 0)
		{
			return head->ports_num;
		}
		head = head->next;
	}
	return AE_ERROR;
}
//function-18

int host_info_base_delete_port(uint8_t *eid, PORT_INFO *port_info)
{
	EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
	if (head == NULL)
	{
		return AE_ERROR;
	}
	while (head != NULL)
	{
		if (memcmp(head->multicast_service_eid, eid, MSLEN) == 0)
		{
			int i = 0;
			for (; i < head->ports_num; ++i)
			{
				if (port_info->port == head->ports[i].port)
				{
					int j = i;
					for (; j < head->ports_num - 1; ++j)
					{
						head->ports[j] = head->ports[j + 1];
					}
					head->ports_num--;
					return AE_OK;
				}
			}
		}
	}
	return AE_ERROR;
}
//function-19

/*
typedef struct
{
	uint16_t outport_index[PORTNUM];
	uint32_t outport_num;
}OUT_PORTS;

//struct FORWARD_INFO{};

typedef struct
{
	uint8_t multicast_service_eid[MSLEN];
	uint8_t pre_ip[IP6LEN];
	uint16_t inport;
	OUT_PORTS outport;
	//struct FORWARD_INFO* next;
}FORWARD_INFO;
*/

int forward_info_base_delete_outport(uint8_t* eid, uint16_t port)
{
	printf("Forward info base deleting is beginning now~\n");
	uint8_t* ip;
	uint16_t inport;
	FORWARD_INFO* head = forward_info_base.forward_info;
	if (head == NULL)
	{
		return AE_ERROR;
	}
	while (head != NULL)
	{
		if (memcmp(eid, head->multicast_service_eid, MSLEN) == 0)
		{
			memcpy(ip, head->pre_ip, IP6LEN);
			inport = head->inport;
			break;
		}
		head = head->next;
	}
	if (head == NULL)
	{
		return AE_ERROR;
	}

	return delete_multicast_forward_info_v2(eid, ip, inport, port);
}
//function-20

/* the end of adding new APIs 2019/10/29 */

void mySleep(int second) 
{
    time_t start;
    start = time(NULL);
    while((time(NULL) - start) < second);
}

/*int member_query(struct local_resource_app_lcore_params *lr_conf)
{
	printf("member_query is starting~\n");
	//uint8_t buf[BUFFLEN] = {0};
	uint8_t *sig = NULL, *mac = NULL, *ip = NULL, *eid = NULL;
	MAC_HEADER *mac_hdr = (MAC_HEADER *)lr_conf->lr->rev_buf;
	mac = mac_hdr->src_mac;
	IPV6_HEADER *ip_hdr = (IPV6_HEADER *)(lr_conf->lr->rev_buf + sizeof(MAC_HEADER));
	ip = ip_hdr->src_ip;
	sig = (uint8_t *)(lr_conf->lr->rev_buf + sizeof(MAC_HEADER) + sizeof(IPV6_HEADER) + sizeof(UDP_HEADER));
	uint16_t port_num = 0; 
	uint32_t pkt_len = 0, sig_len = 0;
	uint8_t src_mac[6] = {0}, dst_mac[6] = {0}, src_ip[16] = {0}, dst_ip[16] = {0};
	uint8_t *query_sig = NULL, *buf = NULL;
	printf("posts info is ready to be got~\n");
	eid = ((SIGNALLING *)sig)->eid;
	uint16_t *port_list = get_outports_from_forward_info_base(eid, &port_num);
	printf("query info is ready to build~\n");
	query_sig = query_info_constructor(eid, mac, ip, port_num, port_list, &sig_len);
	printf("query info is built~\n");
	buf = udp_packet_constructor(src_mac, dst_mac, src_ip, dst_ip, query_sig, sig_len, &pkt_len);
	CHECK_POINTER_RETURN(buf, "Construct packet fail!");
	printf("Construct packet succeed\n");

	while (1)
	{
		int j = 0, k = 0;
		EDGE_SWITCH_INFO* head = edge_switch_info_base.edge_switch_info;
		if (head == NULL)
		{
			printf("edge switch base is empty!\n");
			return AE_ERROR;
		}
		printf("edge_switch_info_base.server_num = %d\n", edge_switch_info_base.server_num);
		printf("the only port = %02X\n", edge_switch_info_base.edge_switch_info->ports[0].port);
		while (head != NULL)
		{
			for (; j < head->ports_num; ++j)
			{
				for (; k <  head->ports[j].hosts_num; ++k)
				{
					//判断上一回合结束时是否不小于3
					if (head->ports[j].hosts[k].count >= 3)
					{
						int ret = 0;
						ret = prune_sig_handler(head->multicast_service_eid, head->ports[j].port, lr_conf->lr, lr_conf->conf);
						CHECK_INT_RETURN(ret, "member_query fail!");
						printf("Handle prune packet~\n");
					}
					//int len = send_packet(buf, BUFFLEN, lr);
					//20191211
					//printf("oops~len = %d\n\n", len);
					head->ports[j].hosts[k].count++;
				}
				k = 0;
			}
			j = 0;
			head = head->next;
		}
		mySleep(1);
	}
	return AE_OK;
}*/