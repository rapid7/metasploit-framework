#ifndef SCSIZE
#define SCSIZE 4096
#endif
unsigned char code[SCSIZE] = "PAYLOAD:";
char szSyncNameS[MAX_PATH] = "Local\\Semaphore:Default\0";
char szSyncNameE[MAX_PATH] = "Local\\Event:Default\0";
