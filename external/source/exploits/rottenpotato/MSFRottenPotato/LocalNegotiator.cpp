#include "stdafx.h"
#include "LocalNegotiator.h"
#include <iostream>

LocalNegotiator::LocalNegotiator()
{
	authResult = -1;
}

void InitTokenContextBuffer(PSecBufferDesc pSecBufferDesc, PSecBuffer pSecBuffer)
{
	pSecBuffer->BufferType = SECBUFFER_TOKEN;
	pSecBuffer->cbBuffer = 0;
	pSecBuffer->pvBuffer = nullptr;

	pSecBufferDesc->ulVersion = SECBUFFER_VERSION;
	pSecBufferDesc->cBuffers = 1;
	pSecBufferDesc->pBuffers = pSecBuffer;
}

int LocalNegotiator::handleType1(char * ntlmBytes, int len)
{
	TCHAR lpPackageName[1024] = L"Negotiate";
	TimeStamp ptsExpiry;

	int status = AcquireCredentialsHandle(
		NULL,
		lpPackageName,
		SECPKG_CRED_INBOUND,
		NULL,
		NULL,
		0,
		NULL,
		&hCred,
		&ptsExpiry);

	if (status != SEC_E_OK)
	{
		printf("Error in AquireCredentialsHandle");
		return -1;
	}

	InitTokenContextBuffer(&secClientBufferDesc, &secClientBuffer);
	InitTokenContextBuffer(&secServerBufferDesc, &secServerBuffer);

	phContext = new CtxtHandle();

	secClientBuffer.cbBuffer = static_cast<unsigned long>(len);
	secClientBuffer.pvBuffer = ntlmBytes;

	ULONG fContextAttr;
	TimeStamp tsContextExpiry;

	status = AcceptSecurityContext(
		&hCred,
		nullptr,
		&secClientBufferDesc,
		ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
		//STANDARD_CONTEXT_ATTRIBUTES,
		SECURITY_NATIVE_DREP,
		phContext,
		&secServerBufferDesc,
		&fContextAttr,
		&tsContextExpiry);

	return status;
}

int LocalNegotiator::handleType2(char * ntlmBytes, int len)
{
	char* newNtlmBytes = (char*) secServerBuffer.pvBuffer;
	if (len >= secServerBuffer.cbBuffer) {
		for (int i = 0; i < len; i++)
		{
			if (i < secServerBuffer.cbBuffer) {
				ntlmBytes[i] = newNtlmBytes[i];
			}
			else {
				ntlmBytes[i] = 0x00;
			}
		}
	}
	else {
		printf("Buffer sizes incompatible - can't replace");
	}

	return 0;
}

int LocalNegotiator::handleType3(char * ntlmBytes, int len)
{
	InitTokenContextBuffer(&secClientBufferDesc, &secClientBuffer);
	InitTokenContextBuffer(&secServerBufferDesc, &secServerBuffer);

	secClientBuffer.cbBuffer = static_cast<unsigned long>(len);
	secClientBuffer.pvBuffer = ntlmBytes;

	ULONG fContextAttr;
	TimeStamp tsContextExpiry;
	int status = AcceptSecurityContext(
		&hCred,
		phContext,
		&secClientBufferDesc,
		ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION,
		//STANDARD_CONTEXT_ATTRIBUTES,
		SECURITY_NATIVE_DREP,
		phContext,
		&secServerBufferDesc,
		&fContextAttr,
		&tsContextExpiry);

	authResult = status;

	return status;
}
