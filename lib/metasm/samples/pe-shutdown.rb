#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# here we will build an executable file that will shut down the machine
# when run
# the header part comes from the factorize sample script
#

require 'metasm'
cpu = Metasm::Ia32.new
cpu.generate_PIC = false
Metasm::PE.compile_c(cpu, DATA.read + <<EOS).encode_file('metasm-shutdown.exe')
int main(void) {
	static HANDLE htok;
	static TOKEN_PRIVILEGES tokpriv;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htok);
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tokpriv.Privileges[0].Luid);
	tokpriv.PrivilegeCount = 1U;
	tokpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(htok, 0, &tokpriv, 0U, NULL, NULL);
	ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_UPGRADE | SHTDN_REASON_FLAG_PLANNED);
	return 0;
}
EOS

__END__
#define EWX_FORCE 0x00000004U
#define EWX_SHUTDOWN 0x00000001U
#define LookupPrivilegeValue LookupPrivilegeValueA
#define NULL ((void *)0)
#define SE_PRIVILEGE_ENABLED (0x00000002UL)
#define SHTDN_REASON_FLAG_PLANNED 0x80000000U
#define SHTDN_REASON_MAJOR_OPERATINGSYSTEM 0x00020000U
#define SHTDN_REASON_MINOR_UPGRADE 0x00000003U
#define TOKEN_ADJUST_PRIVILEGES (0x0020U)
#define TOKEN_QUERY (0x0008U)
#define __TEXT(quote) quote
#define TEXT(quote) __TEXT(quote)
#define SE_SHUTDOWN_NAME TEXT("SeShutdownPrivilege")

typedef int BOOL;
typedef char CHAR;
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef long LONG;
typedef unsigned int UINT;
BOOL ExitWindowsEx __attribute__((dllimport)) __attribute__((stdcall))(UINT uFlags, DWORD dwReason);
HANDLE GetCurrentProcess __attribute__((dllimport)) __attribute__((stdcall))(void);
typedef const CHAR *LPCSTR;
typedef DWORD *PDWORD;
typedef HANDLE *PHANDLE;

struct _LUID {
	DWORD LowPart;
	LONG HighPart;
};
typedef struct _LUID LUID;
BOOL OpenProcessToken __attribute__((dllimport)) __attribute__((stdcall))(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef struct _LUID *PLUID;
BOOL LookupPrivilegeValueA __attribute__((dllimport)) __attribute__((stdcall))(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);

struct _LUID_AND_ATTRIBUTES {
	LUID Luid;
	DWORD Attributes;
};
typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

struct _TOKEN_PRIVILEGES {
	DWORD PrivilegeCount;
	LUID_AND_ATTRIBUTES Privileges[1];
};
typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;
typedef struct _TOKEN_PRIVILEGES TOKEN_PRIVILEGES;
BOOL AdjustTokenPrivileges __attribute__((dllimport)) __attribute__((stdcall))(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
