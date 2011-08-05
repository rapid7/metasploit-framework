#ifndef _METERPRETER_SOURCE_EXTENSION_LANATTACKS_DHCPSERVER_H
#define _METERPRETER_SOURCE_EXTENSION_LANATTACKS_DHCPSERVER_H

const int bufferSize = 4096;
const int dhcpServPort = 67;

const unsigned char Request = 1;
const unsigned char Response = 2;

const unsigned char DHCPDiscover = 1;
const unsigned char DHCPOffer = 2;
const unsigned char DHCPRequest = 3;
const unsigned char DHCPAck = 5;

const char * DHCPMagic = "\x63\x82\x53\x63";

const unsigned char OpDHCPServer = 0x36;
const unsigned char OpLeaseTime = 0x33;
const unsigned char OpSubnetMask = 1;
const unsigned char OpRouter = 3;
const unsigned char OpDns = 6;
const unsigned char OpHostname = 0x0c;
const unsigned char OpEnd = 0xff;

const char * PXEMagic = "\xF1\x00\x74\x7E";
const unsigned char OpPXEMagic = 0xD0;
const unsigned char OpPXEConfigFile = 0xD1;
const unsigned char OpPXEPathPrefix = 0xD2;
const unsigned char OpPXERebootTime = 0xD3;

enum errCodes{
localIpError = 1,
setsockoptError,
wsaStartupError,
invalidSocket,
bindError,
listenError
};

#ifdef WIN32
DWORD WINAPI runDHCPServer(void * keepRunningPtr);
#else
int runDHCPServer(void *keepRunningPtr);
#endif

#endif
