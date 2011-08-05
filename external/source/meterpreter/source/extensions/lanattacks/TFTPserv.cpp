//TFTP server in C++
#include <algorithm>
#include <string.h>
#include <time.h>
#include "TFTPserv.h"

const int bufferSize = 4096;
const int tftpServPort = 69;

const unsigned char OpRead = 1;
const unsigned char OpWrite = 2;
const unsigned char OpData = 3;
const unsigned char OpAck = 4;
const unsigned char OpError = 5;
const unsigned char OpOptAck = 6;

const unsigned char ErrFileNotFound = 1;
const unsigned char ErrAccessViolation = 2;
const unsigned char ErrDiskFull = 3;
const unsigned char ErrIllegalOperation = 4;
const unsigned char ErrUnknownTransferId = 5;
const unsigned char ErrFileExists = 6;
const unsigned char ErrNoSuchUser = 7;
const unsigned char ErrFailedOptNegotiation = 8;

// Creates the TFTP server, passing pointer to C caller
extern "C" void* createTFTPServer(){
	return new TFTPserv();
}
// Destroys the given TFTP server
extern "C" void destroyTFTPServer(void * server){
	delete (TFTPserv *)(server);
}
// Adds a file to the TFTP server, from C caller
extern "C" int addTFTPFile(void * server, char* filename, unsigned int filenamelen, char* file, unsigned int filelen){
	string filenamestr(filename,filenamelen);
	string filestr(file,filelen);
	((TFTPserv*)server)->addFile(filenamestr,filestr);
	return 0;
}
// Starts the TFTP server (in new thread)
extern "C" int startTFTPServer(void * server){
	return ((TFTPserv*)server)->start();
}
// Stops the TFTP server
extern "C" int stopTFTPServer(void * server){
	return ((TFTPserv*)server)->stop();
}

//constructor
TFTPserv::TFTPserv(): fileIndexes(), files(), transfers(){
	index = 0;
	thread = NULL;
	shuttingDown = false;
	smellySock = 0;
}
//htons except returns a binary string
string TFTPserv::htonstring(unsigned short input){
	unsigned short output = htons(input);
	string res((const char*)&output,2);
	return res;
}
//adds a "file" based on name, contents
void TFTPserv::addFile(string filename, string data){
	fileIndexes[filename] = index;
	files[index] = data;
	index++;
}

//checks whether a transfer needs to be marked for resend
void TFTPserv::checkRetransmission(map<string,unsigned int> & transfer){
	unsigned int elapsed = clock() / CLOCKS_PER_SEC - transfer["lastSent"];
	if ( elapsed <= transfer["timeout"] )
		return;
	if (transfer["retries"] >= 3){
		transfers.erase(&transfer);
		return;
	}
	transfer["lastSent"] = 0;
	transfer["retries"] = transfer["retries"] + 1;
}

//Gets a request packet, figures out what to do, and does it
void TFTPserv::dispatchRequest(sockaddr_in &from, string buf){
	unsigned short op = ntohs(*((unsigned short*)buf.c_str()));
	unsigned int currentSpot = 2;
	switch (op){
	case OpRead:{
		currentSpot = buf.find('\x00',2);
		if(currentSpot == -1)
			return;
		string fn(buf.substr(2,currentSpot - 2)); //get filename
		if(fileIndexes.count(fn) == 0) //nonexistant file
			return;
		unsigned int newSpot = buf.find('\x00',currentSpot + 1);
		if(newSpot == -1) //invalid packet format
			return;
		//string mode(buf.substr(currentSpot + 1, newSpot - currentSpot - 1)); //don't really need this

		//New transfer!
		map<string,unsigned int> *transfer = new map<string,unsigned int>();
		(*transfer)["type"] = OpRead;
		(*transfer)["fromIp"] = *((unsigned int *)&from.sin_addr);
		(*transfer)["fromPort"] = from.sin_port;
		(*transfer)["file"] = fileIndexes[fn];
		(*transfer)["block"] = 1;
		(*transfer)["blksize"] = 512;
		(*transfer)["offset"] = 0;
		(*transfer)["timeout"] = 3;
		(*transfer)["lastSent"] = 0;
		(*transfer)["retries"] = 0;
		
		//process_options
		processOptions((struct sockaddr *)&from, sizeof(sockaddr_in), buf, *transfer, newSpot + 1);

		transfers.insert(transfer);
		break;
	}
	case OpAck:{
		//Got an ack
		unsigned short block = ntohs(*((unsigned short*)(buf.c_str() + 2)));
		map<string,unsigned int> *transfer = NULL;
		//Find transfer
		for (set<map<string,unsigned int> *>::iterator it = transfers.begin(); it != transfers.end(); ++it)
			if ((*(*it))["fromIp"] == *((unsigned int *)&from.sin_addr) 
					&& (*(*it))["fromPort"] == from.sin_port
					&& (*(*it))["block"] == block)
				transfer = *it;
		if(transfer == NULL)
			return;
		(*transfer)["offset"] = (*transfer)["offset"] + (*transfer)["blksize"];
		(*transfer)["block"] = (*transfer)["block"] + 1;
		(*transfer)["lastSent"] = 0;
		(*transfer)["retries"] = 0;
		if ((*transfer)["offset"] <= files[(*transfer)["file"]].length())
			return; //not complete
		transfers.erase(transfer); // we're done!
		delete transfer;
	}
	}
}
// Extracts an int option in ascii form; if in range saves it and appends an option ack to replyPacket
void TFTPserv::checkIntOption(const char * optName, int min, int max, string & opt, string & val, map<string,unsigned int> & transfer, string & replyPacket){
	if (opt.compare(optName) != 0)
		return;
	//convert ascii to integer value
	int intval = 0;
	for(unsigned int i = 0; i < val.length(); i++)
		if(val[i] >= '0' && val[i] <= '9')
			intval = intval * 10 + val[i] - '0';
	//Validate it
	if (intval > max)
		intval = max;
	if (intval < min)
		intval = min;
	//Save it
	transfer[optName] = intval;
	//append ack
	replyPacket.append(opt).append(1,(char)0).append(val).append(1,(char)0);
}
//Parses all options from received packet
void TFTPserv::processOptions(struct sockaddr * from, unsigned int fromlen, string buf, map<string,unsigned int> & transfer, unsigned int spot){
	//Start with optack (two byte)
	string data = htonstring(OpOptAck);

	//Loop over options
	unsigned int currentSpot = spot;
	while (currentSpot < buf.length() - 4){
		//Get option
		unsigned int nextSpot = buf.find('\x00',currentSpot);
		if(nextSpot == -1)
			return;
		string opt(buf.substr(currentSpot, nextSpot - currentSpot));

		//Get value
		currentSpot = nextSpot + 1;
		nextSpot = buf.find('\x00',currentSpot);
		if(nextSpot == -1)
			return;
		string val(buf.substr(currentSpot, nextSpot - currentSpot));
		currentSpot = nextSpot + 1;
		for (string::iterator it=opt.begin() ; it < opt.end(); it++ )
			*it = tolower(*it);
		checkIntOption("blksize",8,65464,opt,val,transfer,data);
		checkIntOption("timeout",1,255,opt,val,transfer,data);

		if (opt.compare("tsize") == 0){
			//get length
			unsigned int flen = files[transfer["file"]].length();
			//convert to ascii
			string strlen;
			while(flen > 0){
				strlen.insert(0,1,(char)((flen % 10) + '0'));
				flen = flen / 10;
			}
			data.append(opt).append(1,(char)0).append(strlen).append(1,(char)0);
		}
	}
	//Send packet
	sendto(smellySock, data.c_str(), data.length(), 0, from, fromlen);
}
// Asks server to stop
int TFTPserv::stop(){
	shuttingDown = true;
	DWORD res = 0xffffffff;
	if(thread != NULL)
		res = WaitForSingleObject(thread, 5000);
	thread = NULL;
	return res;
}

// Method to pass to CreateThread
DWORD WINAPI runTFTPServer(void* server){
	return ((TFTPserv*)server)->run();
}

// Starts server
int TFTPserv::start(){
	//get socket
	smellySock = socket(AF_INET, SOCK_DGRAM, 0);
	if (smellySock == -1)
		return -1; // -1=INVALID_SOCKET

	//Se up server socket address
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(tftpServPort);
	server.sin_addr.s_addr = 0; //a.k.a. INADDR_ANY

	// Bind address to socket
	if (bind(smellySock, (struct sockaddr *)&server, sizeof(server)) != 0)
		return GetLastError();

	thread = CreateThread(NULL,0,&runTFTPServer,this,0,NULL);
	if(thread != NULL)
		return ERROR_SUCCESS;
	return GetLastError();
}

//Internal run method that does all the hard work
int TFTPserv::run(){
	// Setup timeout
	fd_set recvSet;
	fd_set sendSet;
	int n;

	//Main packet-handling loop
	shuttingDown = false;
	while (shuttingDown == false){
		FD_ZERO(&recvSet);
		FD_SET(smellySock, &recvSet);
		FD_ZERO(&sendSet);
		//Do we need to check for sent items? Let's see
		for (set<map<string,unsigned int> *>::iterator it = transfers.begin(); it != transfers.end(); ++it){
			if((*(*it))["lastSent"] != 0){
				FD_SET(smellySock, &recvSet);
				break;
			}
		}
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		n = select ( smellySock+1, &recvSet, &sendSet, NULL, &tv );
		if( n == -1 ) 
			break; //Error

		//Get request
		char receiveBuf[bufferSize];
		struct sockaddr client;
		int clientLength = sizeof(client);
		int receiveSize = 0; 
		if ( n != 0) 
			receiveSize = recvfrom(smellySock, receiveBuf, bufferSize, 0, &client, &clientLength);
		if (receiveSize > 0){ 
			string data(receiveBuf, receiveSize);
			dispatchRequest(*((sockaddr_in *)&client),data);
		}
		//Now see if we need to transmit/retransmit another block
		for (set<map<string,unsigned int> *>::iterator it = transfers.begin(); it != transfers.end(); ++it){
			map<string, unsigned int> & transfer = *(*it);
			if(transfer["type"] != OpRead)
				continue;
			if(transfer["lastSent"] != 0){
				checkRetransmission(transfer);
			}else{
				string block = files[transfer["file"]].substr(transfer["offset"],transfer["blksize"]);
				if (block.size() > 0){
					string packet(htonstring(OpData));
					packet.append(htonstring( transfer["block"] ));
					packet.append(block);
					//Send packet
					//first get address
					sockaddr_in client;
					memset((void*)&client,0,sizeof(client));
					client.sin_family = AF_INET;
					*((unsigned int *)&client.sin_addr) = transfer["fromIp"];
					client.sin_port = (unsigned short)transfer["fromPort"];
					//whew. now send
					sendto(smellySock, packet.c_str(), packet.size(), 0, (sockaddr*)&client, sizeof(sockaddr_in));
					transfer["lastSent"] = clock() / CLOCKS_PER_SEC;
				}
			}
		}
	}

#ifdef WIN32
	closesocket(smellySock);
#else
	close(smellySock);
#endif
	return 0;
}
