
#ifdef WIN32
#include <winsock2.h>
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Ws2_32.lib")
#else
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif
#include <string>
#include <set>
#include <sstream>
using namespace std;
#include "dhcpserver.h"

#ifdef WIN32
typedef int socklen_t;
#endif

extern "C" {
void startDHCPServer(void * server){
	*((int*)server) = 1;
	CreateThread(NULL,0,&runDHCPServer,server,0,NULL);
}
void stopDHCPServer(void * server){
	*((int*)server) = 0;
}
//todo
void* createDHCPServer(){
	int* running = new int;
	(*running) = 0;
	return (void*)running;
}
//todo
void destroyDHCPServer(void * server){
	delete ((int*)server);
}
//todo
void setDHCPOption(void * server, char* name, unsigned int namelen, char* opt, unsigned int optlen){
}
}

//Gets IP of default interface, or at least default interface to 8.8.8.8
unsigned int getLocalIp(){
	//get socket
	int smellySock = socket(AF_INET, SOCK_DGRAM, 0);
	if (smellySock == -1)
		return 0; // -1=INVALID_SOCKET
	
	//Se up server socket address
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = 0x08080808; //8.8.8.8
	connect(smellySock, (const sockaddr*) &server, sizeof(server));

	struct sockaddr_in myaddr;
	socklen_t size = sizeof(myaddr);
	getsockname(smellySock, (struct sockaddr*)&myaddr, &size);
#ifdef WIN32
	closesocket(smellySock);
#else
	close(smellySock);
#endif
	return ntohl(*((unsigned int*) & myaddr.sin_addr));
}

// Creates a DHCP option of format type length value
string dhcpoption(unsigned char type, string val){
	string ret(1,type);
	ret.append(1, (char) val.length()).append(val);
	return ret;
}

// Creates a DHCP option with no value
string dhcpoption(unsigned char type){
	string ret(1,type);
	ret.append(1, '\x00');
	return ret;
}

//convert long to IP binary string
string iton(unsigned int ip){
	unsigned int source = htonl(ip);
	string res((char *)&source,4);
	return res;
}

// Runs the DHCP server; exits with 0 on normal shutdown, anything else on error
#ifdef WIN32
DWORD WINAPI runDHCPServer(void *keepRunningPtr){
	/*
	WSADATA w;
	if (WSAStartup(0x0202, &w) != 0)
		return wsaStartupError; //should be running already
		*/
#else
int runDHCPServer(void *keepRunningPtr){
#endif
	int * keepRunning = (int*)keepRunningPtr;

	//All IP-related options are in host byte order
	//get SRVHOST
	unsigned int myIp = getLocalIp();
	if(myIp == 0)
		return localIpError; //No default route?
	string ipString = iton(myIp);
	//get DHCPIPSTART
	unsigned int startIp = myIp + 1; //default start is just above our IP
	unsigned int currentIp = startIp;
	//get DHCPIPEND
	unsigned int endIp = (myIp | 0xFFFFFF00) + 0xFE; //last octet is .254
	//get NETMASK
	unsigned int netmask = 0xFFFFFF00; //default class C
	//get ROUTER
	unsigned int router = myIp; //we are default ROUTER
	//get DNSSERVER
	unsigned int dnsServer = myIp; //we are default DNSSERVER
	//get BROADCAST
	unsigned int broadcast = INADDR_BROADCAST; //Mandatory for some clients
	//get SERVEONCE
	bool serveOnce = true;
	//get PXE
	bool servePXE = true;
	//get HOSTNAME
	string hostname; //hostname to give out
	//get HOSTSTART
	unsigned int servedOver = 0;
	//get DHCP filename
	string fileName("update1");
	fileName.append(128 - fileName.length(), '\x00');
	//get pxelinux conf filename
	string pxeConfigFile("update2");
	string pxePathPrefix("");
	//get DHCP parameters
	unsigned int leaseTime = 600;
	unsigned int relayIp = 0; // relay ip - not currently suported
	unsigned int pxeRebootTime = 2000;

	//get socket
	int smellySock = socket(AF_INET, SOCK_DGRAM, 0);
	if (smellySock == -1)
		return invalidSocket; // -1=INVALID_SOCKET
	
	//Se up server socket address
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(dhcpServPort);
	server.sin_addr.s_addr = 0; //a.k.a. INADDR_ANY

	//Se up broadcast socket address
	struct sockaddr_in broadcastAddr;
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_port = htons(68);
	broadcastAddr.sin_addr.s_addr = htonl(broadcast); //a.k.a. inet_addr("255.255.255.255")
	int value = 1;
	if(setsockopt(smellySock, SOL_SOCKET, SO_BROADCAST, (char*)&value, sizeof(value)) != 0)
		return setsockoptError;

	// Bind address to socket
	if (bind(smellySock, (struct sockaddr *)&server, sizeof(server)) != 0)
		return bindError;

	// Setup timeout
	fd_set sockSet;
	int n;
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100;

	// Setup tracker for served yet
	set<string> served;

	//Main packet-handling loop
	while (true){
		//Wait for request
		FD_ZERO(&sockSet);
		FD_SET(smellySock, &sockSet);
		n = select ( 1, &sockSet, NULL, NULL, &tv ) ;
		if ( n == 0)  //Timeout
			if(keepRunning)
				continue;
			else //we're done!
				break;
		else if( n == -1 ) 
			break; //Error

		//Get request
		char receiveBuf[bufferSize];
		struct sockaddr client;
		socklen_t clientLength = sizeof(client);
		int receiveSize = recvfrom(smellySock, receiveBuf, bufferSize, 0, &client, &clientLength);
		if (receiveSize <= 240) break; //Error would be -1, DHCP packet must be at least 240
		//String-ize it!
		string receivedPacket(receiveBuf,receiveSize);
		char type = receivedPacket.at(0);
		char hwtype = receivedPacket.at(1);
		char hwlen = receivedPacket.at(2);
		char hops = receivedPacket.at(3); 
		string txid = receivedPacket.substr(4,4); //like buf[4..7]
		string elapsed = receivedPacket.substr(8,2);
		string flags = receivedPacket.substr(10,2);
		string clientip = receivedPacket.substr(12,4);
		string givenip = receivedPacket.substr(16,4);
		string nextip = receivedPacket.substr(20,4);
		string receivedRelayip = receivedPacket.substr(24,4);
		string clienthwaddr = receivedPacket.substr(28,hwlen);
		string servhostname = receivedPacket.substr(44,64);
		string filename = receivedPacket.substr(108,128);
		string magic = receivedPacket.substr(236,4);
		
		if(type != Request || magic.compare(DHCPMagic) != 0)
			continue; //Verify DHCP request

		unsigned char messageType = 0;
		bool pxeclient = false;

		// options parsing loop
		unsigned int spot = 240;
		while (spot < receivedPacket.length() - 3){
			unsigned char optionType = receivedPacket.at(spot);
			if (optionType == 0xff)
				break;

			unsigned char optionLen = receivedPacket.at(spot + 1);
			string optionValue = receivedPacket.substr(spot + 2, optionLen);
			spot = spot + optionLen + 2;
			if(optionType == 53)
				messageType = optionValue.at(0);
			else if (optionType == 150)
				pxeclient = true;
		}
		
		if (pxeclient == false && servePXE == true)
			continue;//No tftp server request; ignoring (probably not PXE client)

		// prepare response
		ostringstream pkt;
		pkt << Response;
		pkt << receivedPacket.substr(1,7); //hwtype, hwlen, hops, txid
		string elaspedFlags("\x00\x00\x00\x00",4); //elapsed, flags
		pkt << elaspedFlags; 
		pkt << clientip;
		if (messageType == DHCPDiscover){
			// give next ip address (not super reliable high volume but it should work for a basic server)
			currentIp += 1;
			if (currentIp > endIp)
				currentIp = startIp;
		}
		
		pkt << iton(currentIp);
		pkt << ipString; //next server ip
		pkt << iton(relayIp);
		pkt << receivedPacket.substr(28,16); //client hw address
		pkt << servhostname;
		pkt << fileName;
		pkt << DHCPMagic;
		pkt << "\x35\x01"; //Option

		if (messageType == DHCPDiscover){  //DHCP Discover - send DHCP Offer
			pkt << DHCPOffer;

			// check if already served based on hw addr (MAC address)
			if (serveOnce == true && served.count(clienthwaddr) > 0)
				continue;  //Already served; allowing normal boot

		}else if (messageType == DHCPRequest){ //DHCP Request - send DHCP ACK
			pkt << DHCPAck;

			// now we ignore their discovers (but we'll respond to requests in case a packet was lost)
			served.insert(clienthwaddr);
			if ( servedOver != 0 ) // NOTE: this is sufficient for low-traffic net
				servedOver += 1;

		}else{
			continue; //ignore unknown DHCP request
		}

		// Options!
		pkt << dhcpoption(OpDHCPServer, ipString);
		pkt << dhcpoption(OpLeaseTime, iton(leaseTime));
		pkt << dhcpoption(OpSubnetMask, iton(netmask));
		pkt << dhcpoption(OpRouter, iton(router));
		pkt << dhcpoption(OpDns, iton(dnsServer));
		string pxemagic(PXEMagic,4);
		pkt << dhcpoption(OpPXEMagic, pxemagic);
		pkt << dhcpoption(OpPXEConfigFile, pxeConfigFile);
		pkt << dhcpoption(OpPXEPathPrefix, pxePathPrefix);
		pkt << dhcpoption(OpPXERebootTime, iton(pxeRebootTime));
		if ( hostname.length() > 0 ){
			ostringstream sendHostname;
			sendHostname << hostname;
			if ( servedOver != 0 )
				sendHostname << servedOver;
			pkt << dhcpoption(OpHostname, sendHostname.str());
		}

		pkt << dhcpoption(OpEnd);
		string sendPacket = pkt.str();

		//Send response
		int sent = sendto(smellySock, sendPacket.c_str(), sendPacket.length(), 0, (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
		if (sent != sendPacket.length())
			break; //Error
	}
#ifdef WIN32
	closesocket(smellySock);
#else
	close(smellySock);
#endif
	return 0;
}

