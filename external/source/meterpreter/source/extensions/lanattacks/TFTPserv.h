//TFTP server in C++
#ifndef TFTPserv_H
#define TFTPserv_H

#include <map>
#include <set>
#include <string>
#include <sstream>
using namespace std;

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Ws2_32.lib")
#else
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

//C interface for these functions
extern "C" {
	//creates a new server
	void* createTFTPServer();
	// Adds a file to the TFTP server, from C caller
	int addTFTPFile(void * server, char* filename, unsigned int filenamelen, char* file, unsigned int filelen);
	// Runs the TFTP server
	int startTFTPServer(void * server);
	// Stops the TFTP server
	int stopTFTPServer(void * server);
}

class TFTPserv {
public:
	TFTPserv();// leaving default destructor - should call default destructors for members
	// methods
	int start();
	int stop();
	int run();
	void addFile(string filename, string data);
private:
	bool shuttingDown;
	void* thread;
	int smellySock;
	unsigned int index;
	map<string,unsigned int> fileIndexes;
	map<unsigned int,string> files;
	set<map<string,unsigned int> *> transfers;

	string htonstring(unsigned short input);
	void checkRetransmission(map<string,unsigned int> & transfer);
	void dispatchRequest(sockaddr_in &from, string buf);
	void processOptions(sockaddr * from, unsigned int fromlen, string buf, map<string,unsigned int> & transfer, unsigned int spot);
	void checkIntOption(const char * optName, int min, int max, string & opt, string & val, map<string,unsigned int> & transfer, string & data);
};

#endif

