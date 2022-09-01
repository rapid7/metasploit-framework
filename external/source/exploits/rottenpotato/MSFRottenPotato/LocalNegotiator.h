#define SECURITY_WIN32 

#pragma once
#include <security.h>
#include <schannel.h>
class LocalNegotiator
{
public:
	LocalNegotiator();
	int handleType1(char* ntlmBytes, int len);
	int handleType2(char* ntlmBytes, int len);
	int handleType3(char* ntlmBytes, int len);
	PCtxtHandle phContext;
	int authResult;

private:
	CredHandle hCred;
	SecBufferDesc secClientBufferDesc, secServerBufferDesc;
	SecBuffer secClientBuffer, secServerBuffer;
};

