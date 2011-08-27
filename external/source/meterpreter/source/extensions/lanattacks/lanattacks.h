#ifndef _METERPRETER_SOURCE_EXTENSION_LANATTACKS_LANATTACKS_H
#define _METERPRETER_SOURCE_EXTENSION_LANATTACKS_LANATTACKS_H

#define TLV_TYPE_EXTENSION_LANATTACKS	0


#define TLV_TYPE_LANATTACKS_OPTION					\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_RAW,				\
				TLV_TYPE_EXTENSION_LANATTACKS,		\
				TLV_EXTENSIONS + 1)

#define TLV_TYPE_LANATTACKS_OPTION_NAME				\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_STRING,				\
				TLV_TYPE_EXTENSION_LANATTACKS,		\
				TLV_EXTENSIONS + 2)

#define TLV_TYPE_LANATTACKS_UINT					\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,					\
				TLV_TYPE_EXTENSION_LANATTACKS,		\
				TLV_EXTENSIONS + 3)

#define TLV_TYPE_LANATTACKS_RAW					\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_RAW,					\
				TLV_TYPE_EXTENSION_LANATTACKS,		\
				TLV_EXTENSIONS + 4)

//C interface for DHCP functions
//creates a new server
void* createDHCPServer();
//destroys a server
void destroyDHCPServer(void * server);
// Starts the DHCP server
int startDHCPServer(void * server);
// Stops the DHCP server
int stopDHCPServer(void * server);
// Sets an option in the DHCP server
void setDHCPOption(void * server, char* name, unsigned int namelen, char* opt, unsigned int optlen);
//Gets the log of DHCP served
unsigned char * getDHCPLog(void * server, unsigned long * size);

//C interface for TFTP functions
//creates a new server
void* createTFTPServer();
//destroys a server
void destroyTFTPServer(void * server);
// Adds a file to the TFTP server, from C caller
void addTFTPFile(void * server, char* filename, unsigned int filenamelen, char* file, unsigned int filelen);
// Runs the TFTP server
int startTFTPServer(void * server);
// Stops the TFTP server
int stopTFTPServer(void * server);

#endif
