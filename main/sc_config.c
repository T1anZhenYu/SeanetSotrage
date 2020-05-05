#include <stddef.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_cfgfile.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include "sc_user_config.h"

#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include <arpa/inet.h>


struct config* con = NULL;

struct device {
  char name[256];
  char ipv6[40];
  char mac[13];
  struct device* next;
};

struct config {
  char global_ip[40];
  char enhance_ip[40];
  char time[5];
  struct device* dev;
};

static void freelist(struct device* phead) {
  struct device* pf1;
  struct device* pf2;
  pf1 = phead;
  while (pf1) {
    pf2 = pf1->next;
    free(pf1);
    pf1 = pf2;
  }
}

int sc_config_load(const char* filename) {
  FILE* fp;
  long len;
  char* content;
  cJSON* json;
  fp = fopen(filename, "rb");
  if (NULL == (fp = fopen("test1.json", "rb"))) {
    printf("error\n");
    return;
  }
  fseek(fp, 0, SEEK_END);
  len = ftell(fp);
  printf("len is %d \n", len);
  fseek(fp, 0, SEEK_SET);
  content = (char*)malloc(len + 1);
  fread(content, 1, len, fp);
  fclose(fp);
  // printf("content is %s\n", content);
  json = cJSON_Parse(content);
  if (!json) {
    printf("Error before: [%s]\n", cJSON_GetErrorPtr());
  }
  con = (struct config*)malloc(sizeof(struct config));
  // con = (struct config *)malloc(62);
  cJSON* arrayItem = cJSON_GetObjectItem(json, "global_ip");
  memcpy(con->global_ip, arrayItem->valuestring, 40);
  printf("global_ip is %s\n", con->global_ip);

  arrayItem = cJSON_GetObjectItem(json, "enhance_ip");
  memcpy(con->enhance_ip, arrayItem->valuestring, 40);
  printf("enhance_ip is %s\n", con->enhance_ip);

  arrayItem = cJSON_GetObjectItem(json, "time");
  memcpy(con->time, arrayItem->valuestring, 5);
  printf("time is %s\n", con->time);

  arrayItem = cJSON_GetObjectItem(json, "device");
  cJSON *object, *item;
  int len_num = cJSON_GetArraySize(arrayItem);
  printf("array len is %d\n", len_num);

  struct device* head = NULL;
  struct device* p1 = NULL;
  struct device* p2 = NULL;
  p1 = (struct device*)malloc(sizeof(struct device));
  // p1 = (struct device *)malloc(62);
  p2 = p1;
  int i = 0;
  int first = 1;
  for (i = 0; i < len_num + 1; i++) {
    if (i != len_num) {
      object = cJSON_GetArrayItem(arrayItem, i);
      strcpy(p1->name, cJSON_GetObjectItem(object, "name")->valuestring);
      strcpy(p1->ipv6, cJSON_GetObjectItem(object, "ipv6")->valuestring);
      strcpy(p1->mac, cJSON_GetObjectItem(object, "mac")->valuestring);
      printf("name is %s\n", p1->name);
      printf("mac = %s\n", p1->mac);
      if (first) {
        // con->dev=p1;
        head = p1;
        first = 0;
      } else {
        p2->next = p1;
      }
      p2 = p1;
      p1 = NULL;
      p1 = (struct device*)malloc(sizeof(struct device));
    } else {
      p2->next = NULL;
    }
  }
  con->dev = head;
  free(content);
  cJSON_Delete(json);
}

int sc_config_global_resolve_node_get(uint8_t* ipv6_addr) {
  if (unlikely(ipv6_addr == NULL)) {
    return -EINVAL;
  }
  if (unlikely(!con)) {
    return -ENOENT;
  }
  if (inet_pton(AF_INET6, con->global_ip, ipv6_addr) != 1) {
    return -EFAULT;
  }
  return 0;
}

int sc_config_enhanced_resolve_node_get(uint8_t* ipv6_addr, int16_t* latency) {
  if (unlikely(ipv6_addr == NULL || latency == NULL)) {
    return -EINVAL;
  }
  if (unlikely(!con)) {
    return -ENOENT;
  }
  if (inet_pton(AF_INET6, con->enhance_ip, ipv6_addr) != 1) {
    return -EFAULT;
  }
  *latency = con->time;
  return 0;
}

int sc_config_ethdev_get(const char* ifname, uint8_t* ether_addr,
                         uint8_t* ipv6_addr) {
  if (unlikely(ifname == NULL || ether_addr == NULL || ipv6_addr == NULL)) {
    return -EINVAL;
  }
  if (unlikely(!con)) {
    return -ENOENT;
  }
  struct device* pf1;
  struct device* pf2;
  pf1 = con->dev;
  while (pf1) {
    pf2 = pf1->next;
    free(pf1);
    pf1 = pf2;
  }

  return -ENOENT;
  return 0;
}

