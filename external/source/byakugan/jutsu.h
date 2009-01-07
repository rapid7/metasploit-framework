#define DEFAULT_BUFLEN	2096
#define DEFAULT_PORT	"1911"

// Request Types
#define	EXECUTE		0x0
#define GO			0x1
#define	BREAK		0x2
#define RESTART		0x3
#define ADDBUF		0x4

// Corruption Types
#define	CLEAN		0x0
#define TOUPPER		0x1
#define TOLOWER		0x2
#define	TOUNICODE	0x3
#define	NONSTD		0x4
#define TRUNCATED	0x5

struct debugState {
    ULONG   currentState; 
};

struct requestQueue {
    ULONG           length;
    struct request  *head;
};

struct request {
	USHORT	type;
	USHORT	length;
	BYTE	*data;

	struct request	*next;
};

struct requestHeader {
	USHORT	type;
	USHORT	length;
};

struct trackedBuf {
	char	*bufName;
	char	*bufPatt;
	USHORT	found;

	struct bufInstance	*instances;
	struct trackedBuf	*next;
	struct trackedBuf	*prev;
};

struct bufInstance {
	ULONG64	address;
	USHORT	corruption;
	ULONG	truncLength;

	struct bufInstance	*next;
};

struct trackedVal {
    char    *valName;
    BYTE    valSize;
    ULONG   candidates;

    struct  valInstance *instances;
    struct  trackedVal  *next;
};

struct valInstance {
    ULONG64 address;

    struct valInstance *next;
};


void    helpJutsu(void);
void    bindJutsu(char *);
void	searchOpcodes(char *);
DWORD WINAPI listenJutsu(LPVOID lpvParam);
void	parseJutsu(char *, ULONG);
void	identBufJutsu(char *, char *);
void	rmBufJutsu(char *);
void	listTrackedBufJutsu(void);
void	showRequestsJutsu(void);
void	hunterJutsu(void);
void	returnAddressHuntJutsu(void);
void	trackValJutsu(char *name, DWORD size, DWORD value);
ULONG64 allocateMemoryBlock(unsigned long); 
ULONG64 searchMemory(unsigned char * byteBuffer, unsigned long length);
DWORD   findAllVals(unsigned char *byteBuffer, BYTE size, struct valInstance **instance);

// Handlers
void	executeJutsu(struct request *);
void	goJutsu(struct request *);
void	breakJutsu(struct request *);
void	restartJutsu(struct request *);
void	addbufJutsu(struct request *);
