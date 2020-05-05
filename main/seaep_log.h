#ifndef SEAEP_LOG_H
#define SEAEP_LOG_H
#include <time.h>

//#define SERVER //for dang
//#define AP //FOR ap
#define ROUTER

#ifdef ROUTER
#define IF_NAME "p4p2"
#endif

#ifdef SERVER
#define IF_NAME "em2"
#define LOG_FILE
#endif

#ifdef AP
#define IF_NAME "eth0.2"
#define LOG_FILE
#endif

#ifdef ANDROID
#define IF_NAME "wlan0"
#endif

//#define LOG_FILE


#define LOG_FILE_NAME "/tmp/seaep.log"

#define FILE_LOG_PRINT(format, ...)                      \
do{                                                            \
    char buffer[1024]={0};    \
    time_t time_log = time(NULL);   \
    struct tm* t = localtime(&time_log);   \
    snprintf(buffer, 1024, "%02d-%02d %02d:%02d:%02d     " format, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,##__VA_ARGS__ );\
    FILE* fd = fopen(LOG_FILE_NAME, "a");\
    if ( fd != NULL ) {\
        fwrite( buffer, strlen(buffer), 1, fd );\
        fflush( fd );\
        fclose( fd );\
    }\
}while(0);

#define DEBUG 


#ifndef DEBUG

#define seaep_log(...)
#define seaep_message(...)
#define seaep_warning(...)
#define seaep_err(...)

#else

#ifdef ANDROID
#include <android/log.h>
#ifndef LOG_TAG
#define LOG_TAG "SEAEP"
#define LOGINFO_TAG "SEAEPINFO"

#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOGINFO_TAG, __VA_ARGS__) 
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#endif
#define seaep_log LOGD
#define seaep_info LOGI
#define seaep_message LOGI
#define seaep_warning LOGI
#define seaep_err LOGI
#else

#ifdef LOG_FILE
#define seaep_log FILE_LOG_PRINT
#define seaep_message FILE_LOG_PRINT
#define seaep_warning FILE_LOG_PRINT
#define seaep_info FILE_LOG_PRINT
#define seaep_err FILE_LOG_PRINT
#else
#define seaep_log printf
#define seaep_info printf
#define seaep_message printf
#define seaep_warning printf
#define seaep_err printf
#endif


#endif



#endif

#endif

