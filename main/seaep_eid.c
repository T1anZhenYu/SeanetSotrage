#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/types.h>
#include "seaep_log.h"
#include "seaep_eid.h"

/*
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
*/
#ifndef uint32_t
typedef int int32_t;
typedef unsigned int uint32_t;
#endif


#define SEAHASH_ROTL(a,b) (SEAHASH_tmp=(a),((SEAHASH_tmp>>(32-b))&(0x7fffffff>>(31-b)))|(SEAHASH_tmp<<b))
#define SEAHASH_F(B,C,D,t) ((t<40)?((t<20)?((B&C)|((~B)&D)):(B^C^D)):((t<60)?((B&C)|(B&D)|(C&D)):(B^C^D)))
int32_t SEAHASH_tmp;
char* StrSEAHASH(const char* str, int32_t length){
    static char seahash[40+1];
    char *pp, *ppend;
    int32_t l, i, K[80], W[80], TEMP, A, B, C, D, E, H0, H1, H2, H3, H4;
    H0 = 0x67452301, H1 = 0xEFCDAB89, H2 = 0x98BADCFE, H3 = 0x10325476, H4 = 0xC3D2E1F0;
    for (i = 0; i < 20; K[i++] = 0x5A827999);
    for (i = 20; i < 40; K[i++] = 0x6ED9EBA1);
    for (i = 40; i < 60; K[i++] = 0x8F1BBCDC);
    for (i = 60; i < 80; K[i++] = 0xCA62C1D6);
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)malloc((uint32_t)l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128,i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0,i++);
    *((int32_t*)(pp + l - 4)) = length << 3;
    *((int32_t*)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((int32_t*)pp)[i], i++);
        for (i = 16; i < 80; W[i] = SEAHASH_ROTL((W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]), 1), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4;
        for (i = 0; i < 80; i++){
            TEMP = SEAHASH_ROTL(A, 5) + SEAHASH_F(B, C, D, i) + E + W[i] + K[i];
            E = D, D = C, C = SEAHASH_ROTL(B, 30), B = A, A = TEMP;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E;
    }
    free(pp - l);

    memcpy(seahash,&H0,4);
    memcpy(seahash+4,&H1,4);
    memcpy(seahash+8,&H2,4);
    memcpy(seahash+12,&H3,4);
    memcpy(seahash+16,&H4,4); 
    //seaep_log("StrSEAHASH 11\n");

    //sprintf(seahash, "%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4);
    return seahash;
}





char* getmac() {
#define MAXINTERFACES 16
    int fd, interface;
    struct ifreq buf[MAXINTERFACES];
    struct ifconf ifc;
    static char mac[13] = {0};

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        int i = 0;
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = (caddr_t)buf;
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            interface = ifc.ifc_len / sizeof(struct ifreq);
            //printf("interface num is %d\n", interface);
            while (i < interface)
            {
                //printf("net device %s\n", buf[i].ifr_name);
                if (!(ioctl(fd, SIOCGIFHWADDR, (char *)&buf[i])))
                {
                    sprintf(mac, "%02X%02X%02X%02X%02X%02X",
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[0],
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[1],
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[2],
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[3],
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[4],
                            (unsigned char)buf[i].ifr_hwaddr.sa_data[5]);
                    //printf("%s",mac);
                    if (strcmp(mac, "000000000000") != 0) return mac;
                    //printf("HWaddr %s\n", mac);
                }
                i++;
            }
        }
    }
    return mac;
}





char* gettm() {
    struct timeval time_now = {0};
    //long time_sec = 0;
    //long time_mil = 0;
    long time_mic = 0;
    gettimeofday(&time_now,NULL);
    //time_sec = time_now.tv_sec;
    //time_mil = time_sec * 1000 + time_now.tv_usec/1000;
    time_mic = time_now.tv_sec*1000*1000 + time_now.tv_usec;
    static char t[20];
    sprintf(t,"%ld",time_mic);
    return t;
}

char* geteid() {
    char* mac=getmac();

    char* t=gettm();
    static char* hashout;

    char *out = (char *) malloc(strlen(mac) + strlen(t)+1);
    sprintf(out, "%s%s", mac, t);
    //printf("%s\n", out);
    //printf("%ld\n", strlen(out));

    char* outhash = StrSEAHASH(out, strlen(out));
    free(out);

    return outhash;
}

int get_device_eid(unsigned char device_eid[EID_LEN])
{
    char* mac=getmac();

    char* t="20190520000000";

    char *out = (char *) malloc(strlen(mac) + strlen(t)+1);
    sprintf(out, "%s%s", mac, t);
    //printf("%s\n", out);
    //printf("%ld\n", strlen(out));

    char* outhash = StrSEAHASH(out, strlen(out));
    free(out);
    memcpy(device_eid,outhash,EID_LEN);

    return 0;
}


