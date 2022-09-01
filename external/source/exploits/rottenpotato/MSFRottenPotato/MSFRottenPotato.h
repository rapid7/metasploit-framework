// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MSFROTTENPOTATO_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MSFROTTENPOTATO_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MSFROTTENPOTATO_EXPORTS
#define MSFROTTENPOTATO_API __declspec(dllexport)
#else
#define MSFROTTENPOTATO_API __declspec(dllimport)
#endif
#include "Objidl.h"
#include "BlockingQueue.h"
#include "LocalNegotiator.h"

// This class is exported from the MSFRottenPotato.dll
class MSFROTTENPOTATO_API CMSFRottenPotato {
private:
	BlockingQueue<char*>* comSendQ;
	BlockingQueue<char*>* rpcSendQ;
	static DWORD WINAPI staticStartRPCConnection(void * Param);
	static DWORD WINAPI staticStartCOMListener(void * Param);
	static int newConnection;
	int processNtlmBytes(char* bytes, int len);
	int findNTLMBytes(char * bytes, int len);

public:
	CMSFRottenPotato(void);
	int startRPCConnection(void);
	DWORD startRPCConnectionThread();
	DWORD startCOMListenerThread();
	int startCOMListener(void);
	int triggerDCOM();
	LocalNegotiator *negotiator;
};
