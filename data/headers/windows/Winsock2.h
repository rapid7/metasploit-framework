//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_GGP 3
#define IPPROTO_TCP 6
#define IPPROTO_PUP 12
#define IPPROTO_UDP 17
#define IPPROTO_IDP 22
#define IPPROTO_ND  77
#define IPPROTO_RAW 255
#define IPPROTO_MAX 256
#define IPPORT_ECHO 7
#define IPPORT_DISCARD  9
#define IPPORT_SYSTAT 11
#define IPPORT_DAYTIME 13
#define IPPORT_NETSTAT 15
#define IPPORT_FTP 21
#define IPPORT_TELNET 23
#define IPPORT_SMTP 25
#define IPPORT_TIMESERVER 37
#define IPPORT_NAMESERVER 42
#define IPPORT_WHOIS 43
#define IPPORT_MTP 57
#define IPPORT_TFTP 69
#define IPPORT_RJE 77
#define IPPORT_FINGER 79
#define IPPORT_TTYLINK 87
#define IPPORT_SUPDUP 95
#define IPPORT_EXECSERVER 512
#define IPPORT_LOGINSERVER 513
#define IPPORT_CMDSERVER 514
#define IPPORT_EFSSERVER 520
#define IPPORT_BIFFUDP 512
#define IPPORT_WHOSERVER 513
#define IPPORT_ROUTESERVER 520
#define IPPORT_RESERVED 1024
#define IMPLINK_IP 155
#define IMPLINK_LOWEXPER 156
#define IMPLINK_HIGHEXPER 158
#define WSADESCRIPTION_LEN 256
#define WSASYS_STATUS_LEN 128
#define SD_RECEIVE 0x00
#define SD_SEND 0x01
#define SD_BOTH 0x02
#define FD_SETSIZE 64
#define WSA_INVALID_HANDLE 6
#define WSA_NOT_ENOUGH_MEMORY 8
#define WSA_INVALID_PARAMETER 87
#define WSA_OPERATION_ABORTED 995
#define WSA_IO_INCOMPLETE 996
#define WSA_IO_PENDING 997
#define WSAEINTR 10004
#define WSAEBADF 10009
#define WSAEACCES 10013
#define WSAEFAULT 10014
#define WSAEINVAL 10022
#define WSAEMFILE 10024
#define WSAEWOULDBLOCK 10035
#define WSAEINPROGRESS 10036
#define WSAEALREADY 10037
#define WSAENOTSOCK 10038
#define WSAEDESTADDRREQ 10039
#define WSAEMSGSIZE 10040
#define WSAEPROTOTYPE 10041
#define WSAENOPROTOOPT 10042
#define WSAEPROTONOSUPPORT 10043
#define WSAESOCKTNOSUPPORT 10044
#define WSAEOPNOTSUPP 10045
#define WSAEPFNOSUPPORT 10046
#define WSAEAFNOSUPPORT 10047
#define WSAEADDRINUSE 10048
#define WSAEADDRNOTAVAIL 10049
#define WSAENETDOWN 10050
#define WSAENETUNREACH 10051
#define WSAENETRESET 10052
#define WSAECONNABORTED 10053
#define WSAECONNRESET 10054
#define WSAENOBUFS 10055
#define WSAEISCONN 10056
#define WSAENOTCONN 10057
#define WSAESHUTDOWN 10058
#define WSAETOOMANYREFS 10059
#define WSAETIMEDOUT 10060
#define WSAECONNREFUSED 10061
#define WSAELOOP 10062
#define WSAENAMETOOLONG 10063
#define WSAEHOSTDOWN 10064
#define WSAEHOSTUNREACH 10065
#define WSAENOTEMPTY 10066
#define WSAEPROCLIM 10067
#define WSAEUSERS 10068
#define WSAEDQUOT 10069
#define WSAESTALE 10070
#define WSAEREMOTE 10071
#define WSASYSNOTREADY 10091
#define WSAVERNOTSUPPORTED 10092
#define WSANOTINITIALISED 10093
#define WSAEDISCON 10101
#define WSAENOMORE 10102
#define WSAECANCELLED 10103
#define WSAEINVALIDPROCTABLE 10104
#define WSAEINVALIDPROVIDER 10105
#define WSAEPROVIDERFAILEDINIT 10106
#define WSASYSCALLFAILURE 10107
#define WSASERVICE_NOT_FOUND 10108
#define WSATYPE_NOT_FOUND 10109
#define WSA_E_NO_MORE 10110
#define WSA_E_CANCELLED 10111
#define WSAEREFUSED 10112
#define WSAHOST_NOT_FOUND 11001
#define WSATRY_AGAIN 11002
#define WSANO_RECOVERY 11003
#define WSANO_DATA 11004
#define WSA_QOS_RECEIVERS 11005
#define WSA_QOS_SENDERS 11006
#define WSA_QOS_NO_SENDERS 11007
#define WSA_QOS_NO_RECEIVERS 11008
#define WSA_QOS_REQUEST_CONFIRMED 11009
#define WSA_QOS_ADMISSION_FAILURE 11010
#define WSA_QOS_POLICY_FAILURE 11011
#define WSA_QOS_BAD_STYLE 11012
#define WSA_QOS_BAD_OBJECT 11013
#define WSA_QOS_TRAFFIC_CTRL_ERROR 11014
#define WSA_QOS_GENERIC_ERROR 11015
#define WSA_QOS_ESERVICETYPE 11016
#define WSA_QOS_EFLOWSPEC 11017
#define WSA_QOS_EPROVSPECBUF 11018
#define WSA_QOS_EFILTERSTYLE 11019
#define WSA_QOS_EFILTERTYPE 11020
#define WSA_QOS_EFILTERCOUNT 11021
#define WSA_QOS_EOBJLENGTH 11022
#define WSA_QOS_EFLOWCOUNT 11023
#define WSA_QOS_EUNKOWNPSOBJ 11024
#define WSA_QOS_EPOLICYOBJ 11025
#define WSA_QOS_EFLOWDESC 11026
#define WSA_QOS_EPSFLOWSPEC 11027
#define WSA_QOS_EPSFILTERSPEC 11028
#define WSA_QOS_ESDMODEOBJ 11029
#define WSA_QOS_ESHAPERATEOBJ 11030
#define WSA_QOS_RESERVED_PETYPE 11031
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_IPX 6
#define AF_APPLETALK 16
#define AF_NETBIOS 17
#define AF_INET6 23
#define AF_IRDA 26
#define AF_BTH 32
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR (-1)
#define AI_PASSIVE                  0x00000001
#define AI_CANONNAME                0x00000002
#define AI_NUMERICHOST              0x00000004
#define AI_NUMERICSERV              0x00000008
#define AI_ALL                      0x00000100
#define AI_ADDRCONFIG               0x00000400
#define AI_V4MAPPED                 0x00000800
#define AI_NON_AUTHORITATIVE        0x00004000
#define AI_SECURE                   0x00008000
#define AI_RETURN_PREFERRED_NAMES   0x00010000
#define AI_FQDN                     0x00020000
#define AI_FILESERVER               0x00040000
#define MAX_PROTOCOL_CHAIN 7
#define WSAPROTOCOL_LEN  255
#define SOMAXCONN 0x7fffffff

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef u_int SOCKET;
typedef unsigned int GROUP;
typedef ULONG SERVICETYPE;

struct sockaddr {
  u_short sa_family;
  char  sa_data[14];
} SOCKADDR;

typedef struct WSAData {
  WORD           wVersion;
  WORD           wHighVersion;
  char           szDescription[WSADESCRIPTION_LEN+1];
  char           szSystemStatus[WSASYS_STATUS_LEN+1];
  unsigned short iMaxSockets;
  unsigned short iMaxUdpDg;
  char       *lpVendorInfo;
} WSADATA, *LPWSADATA;

typedef struct addrinfo {
  int             ai_flags;
  int             ai_family;
  int             ai_socktype;
  int             ai_protocol;
  size_t          ai_addrlen;
  char            *ai_canonname;
  struct sockaddr  *ai_addr;
  struct addrinfo  *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef struct fd_set {
  u_int  fd_count;
  SOCKET fd_array[FD_SETSIZE];
} fd_set;

typedef struct in_addr {
  union {
    struct {
      u_char s_b1,s_b2,s_b3,s_b4;
    } S_un_b;
    struct {
      u_short s_w1,s_w2;
    } S_un_w;
    u_long S_addr;
  } S_un;
} IN_ADDR, *PIN_ADDR, *LPIN_ADDR;

struct sockaddr_in {
  short sin_family;
  u_short sin_port;
  struct in_addr sin_addr;
  char sin_zero[8];
};

struct sockproto {
  u_short sp_family;
  u_short sp_protocol;
};

typedef struct hostent {
  char *h_name;
  char **h_aliases;
  short h_addrtype;
  short h_length;
  char **h_addr_list;
} HOSTENT, *PHOSTENT, *LPHOSTENT;

typedef struct _WSAPROTOCOLCHAIN {
  int ChainLen;
  DWORD ChainEntries[MAX_PROTOCOL_CHAIN];
} WSAPROTOCOLCHAIN, *LPWSAPROTOCOLCHAIN;

typedef struct _WSAPROTOCOL_INFO {
  DWORD            dwServiceFlags1;
  DWORD            dwServiceFlags2;
  DWORD            dwServiceFlags3;
  DWORD            dwServiceFlags4;
  DWORD            dwProviderFlags;
  GUID             ProviderId;
  DWORD            dwCatalogEntryId;
  WSAPROTOCOLCHAIN ProtocolChain;
  int              iVersion;
  int              iAddressFamily;
  int              iMaxSockAddr;
  int              iMinSockAddr;
  int              iSocketType;
  int              iProtocol;
  int              iProtocolMaxOffset;
  int              iNetworkByteOrder;
  int              iSecurityScheme;
  DWORD            dwMessageSize;
  DWORD            dwProviderReserved;
  TCHAR            szProtocol[WSAPROTOCOL_LEN+1];
} WSAPROTOCOL_INFO, *LPWSAPROTOCOL_INFO;

typedef struct _WSABUF
{
  ULONG len;
  CHAR* buf;
} WSABUF, *LPWSABUF;

typedef struct _FLOWSPEC {
  unsigned int      TokenRate;
  unsigned int      TokenBucketSize;
  unsigned int      PeakBandwidth;
  unsigned int      Latency;
  unsigned int      DelayVariation;
  SERVICETYPE       ServiceType;
  unsigned int      MaxSduSize;
  unsigned int      MinimumPolicedSize;
} FLOWSPEC, *PFLOWSPEC, *LPFLOWSPEC;

typedef struct _QUALITYOFSERVICE {
  FLOWSPEC           SendingFlowspec;
  FLOWSPEC           ReceivingFlowspec;
  WSABUF             ProviderSpecific;
} QOS, *LPQOS;

typedef int (CALLBACK *LPCONDITIONPROC)(LPWSABUF, LPWSABUF, LPQOS, LPQOS, LPWSABUF, LPWSABUF, GROUP *, DWORD);
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in *PSOCKADDR_IN;
typedef struct sockaddr_in *LPSOCKADDR_IN;

WINAPI int WSAStartup __attribute__((dllimport))(WORD, LPWSADATA);
WINAPI int WSACleanup __attribute__((dllimport))();
WINAPI int getaddrinfo __attribute__((dllimport))(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
WINAPI SOCKET socket __attribute__((dllimport))(int, int, int);
WINAPI void freeaddrinfo __attribute__((dllimport))(struct addrinfo*);
WINAPI int closesocket __attribute__((dllimport))(SOCKET);
WINAPI int bind __attribute__((dllimport))(SOCKET, const struct sockaddr*, int);
WINAPI SOCKET accept __attribute__((dllimport))(SOCKET, struct sockaddr*, int*);
WINAPI BOOL AcceptEx __attribute__((dllimport))(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
WINAPI int connect __attribute__((dllimport))(SOCKET, const struct sockaddr*, int);
WINAPI int gethostname __attribute__((dllimport))(char*, int);
WINAPI int listen __attribute__((dllimport))(SOCKET, int);
WINAPI int recv __attribute__((dllimport))(SOCKET, char*, int, int);
WINAPI int recvfrom __attribute__((dllimport))(SOCKET, char*, int, int, struct sockaddr*, int*);
WINAPI int send __attribute__((dllimport))(SOCKET, char*, int, int);
WINAPI int sendto __attribute__((dllimport))(SOCKET, char*, int, int, const struct sockaddr*, int);
WINAPI int select __attribute__((dllimport))(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
WINAPI int setsockopt __attribute__((dllimport))(SOCKET, int, int, const char*, int);
WINAPI char* inet_ntoa __attribute__((dllimport))(struct in_addr);
WINAPI unsigned long inet_addr __attribute__((dllimport))(const char*);
WINAPI int shutdown __attribute__((dllimport))(SOCKET, int);
WINAPI u_short htons __attribute__((dllimport))(u_short);
WINAPI u_long htonl __attribute__((dllimport))(u_long);
WINAPI struct hostent* gethostbyname __attribute__((dllimport))(const char*);
WINAPI struct hostent* gethostbyaddr __attribute__((dllimport))(const char*, int, int);
WINAPI int WSAGetLastError __attribute__((dllimport))();
WINAPI SOCKET WSASocket __attribute__((dllimport))(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
WINAPI SOCKET WSAAccept __attribute__((dllimport))(SOCKET, struct sockaddr*, LPINT, LPCONDITIONPROC, DWORD_PTR);
