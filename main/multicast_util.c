#include <stdio.h>
#include "multicast_ae.h"

#define PROCBUFSIZ                  1024
#define _PATH_PROC_NET_DEV        "/proc/net/dev"

int check_root() {
	/* Root id = 0 */
	if (geteuid() == 0) {
		return AE_OK;
	} else {
		printf("multicast ae ERROR: Permission denied.\n");
		return AE_ERROR;
	}
}

char * interface_name_cut (char *buf, char **name) {
    char *stat;
    /* Skip white space.  Line will include header spaces. */
    while (*buf == ' ')
        buf++;
    *name = buf;
    /* Cut interface name. */
    stat = strrchr(buf, ':');
    *stat++ = '\0';
    return stat;
}
 
int check_interface_fromproc(char *interface) {
    FILE *fp;
    char buf[PROCBUFSIZ];
    struct interface *ifp;
    char *name;

    /* Open /proc/net/dev. */
    fp = fopen(_PATH_PROC_NET_DEV, "r");
    if (fp == NULL) {   
        printf("open proc file error\n");
        return -1; 
    }   

    /* Drop header lines. */
    fgets(buf, PROCBUFSIZ, fp);
    fgets(buf, PROCBUFSIZ, fp);

    /* Only allocate interface structure.  Other jobs will be done in
     if_ioctl.c. */
    while (fgets(buf, PROCBUFSIZ, fp) != NULL) {   
        interface_name_cut(buf, &name);
        if (strcmp(interface,name)==0)
            return 1;
    }   
    fclose(fp);
    return 0;
}

int check_device(char *interface) {
	if (check_interface_fromproc(interface) == 1) {
		return AE_OK;
	} else {
		return AE_ERROR;
	}
}
