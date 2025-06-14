//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//

#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define true 1
#define false 0
#define VOID void
#define _tWinMain WinMain
#define CALLBACK __stdcall
#define WINAPI __stdcall
#define APIENTRY WINAPI
#define BUFSIZ  512
#define _INTERNAL_BUFSIZ 4096
#define _SMALL_BUFSIZ 512
#define _NSTREAM_ 512
#define _IOB_ENTRIES 20
#define RAND_MAX 0x7fff
#define EOF (-1)
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_SET 0
#define FILENAME_MAX 260
#define FOPEN_MAX 20
#define _SYS_OPEN 20
#define _TMP_MAX_S 2147483647
#define stdin (&__iob_func()[0])
#define stdout (&__iob_func()[1])
#define stderr (&__iob_func()[2])
#define _IOREAD 0x0001
#define _IOWRT 0x0002
#define _IOFBF 0x0000
#define _IOLBF 0x0040
#define _IONBF 0x0004
#define _IOMYBUF 0x0008
#define _IOEOF 0x0010
#define _IOERR 0x0020
#define _IOSTRG 0x0040
#define _IORW 0x0080
#define _TWO_DIGIT_EXPONENT 0x1
#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3

typedef char CHAR;
typedef CHAR* PCHAR;
typedef const char* LPCTSTR;
typedef const char* LPCSTR;
typedef const CHAR* PCSTR;
typedef char* LPSTR;
typedef char* LPTSTR;
typedef CHAR* PSTR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned int DWORD32;
typedef WORD* LPWORD;
typedef long HRESULT;
typedef long LONG;
typedef float FLOAT;
typedef DWORD COLORREF;
typedef WORD ATOM;
typedef BYTE BOOLEAN;
typedef void* HANDLE;
typedef HANDLE SC_HANDLE;
typedef HANDLE HINSTANCE;
typedef HINSTANCE HMODULE;
typedef HANDLE HHOOK;
typedef HANDLE HCONV;
typedef HANDLE HCONFLIST;
typedef HANDLE HFONT;
typedef HANDLE HGLOBAL;
typedef HANDLE HICON;
typedef HANDLE HKEY;
typedef HANDLE HGLOBAL;
typedef HKEY* PHKEY;
typedef HANDLE HKL;
typedef unsigned char UCHAR;
typedef char TCHAR;
typedef char CCHAR;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned int UINT_PTR;
typedef unsigned long ULONG;
typedef unsigned long ULONG_PTR;
typedef long* LPLONG;
typedef long LONG_PTR;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef unsigned int size_t;
typedef size_t* PSIZE_T;
typedef DWORD* LPDWORD;
typedef DWORD* PDWORD;
typedef HANDLE* LPHANDLE;
typedef HANDLE* PHANDLE;
typedef unsigned short u_short;
typedef BYTE* LPBYTE;
typedef BYTE* PBYTE;
typedef void* PVOID;
typedef void* LPVOID;
typedef void* LPCVOID;
typedef ULONG_PTR DWORD_PTR;
typedef void* HWND;
typedef int BOOL;
typedef int bool;
typedef BOOL* PBOOL;
typedef LONG_PTR LRESULT;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LPARAM;
typedef long NTSTATUS;
typedef ULONG* PULONG;
typedef ULONG REGSAM;
typedef LRESULT (CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);
typedef __stdcall int (*FARPROC)();
typedef struct _iobuf FILE;
typedef long fpos_t;
typedef int* LPINT;

typedef struct {
   unsigned int gp_offset;
   unsigned int fp_offset;
   void *overflow_arg_area;
   void *reg_save_area;
} va_list[1];