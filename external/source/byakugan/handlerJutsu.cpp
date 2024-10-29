#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "byakugan.h"
#include "jutsu.h"
#include "msfpattern.h"

void    executeJutsu(struct request *execReq) {
	g_ExtControl->Execute(DEBUG_OUTCTL_THIS_CLIENT,  (PCSTR) execReq->data, 
			DEBUG_EXECUTE_ECHO | DEBUG_EXECUTE_NO_REPEAT);

	g_ExtClient->FlushCallbacks();
}

void    goJutsu(struct request *) {
}

void    breakJutsu(struct request *) {
}

void    addbufJutsu(struct request *) {
}

void    restartJutsu(struct request *) {
}

