//#define DEBUG

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout)
#define LOGD(...) __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout)
#else
#define LOGV(...) 
#define LOGD(...) 
#endif

