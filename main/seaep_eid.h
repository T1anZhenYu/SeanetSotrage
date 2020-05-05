#ifndef SEAEP_EID_H
#define SEAEP_EID_H
#ifdef __cplusplus
extern "C" {
#endif

#define EID_LEN 20

char* geteid(void) ;
int get_device_eid(unsigned char device_eid[EID_LEN]) ;
char* getmac(void);

#ifdef __cplusplus
}
#endif

#endif

