;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008R2, 2008, 2003, XP
; Architecture: x64
; Version: 1.0 (Jan 2010)
; Size: 296 bytes
; Build: >build.py remotethread
;-----------------------------------------------------------------------------;

; Function to create a remote thread via ntdll!RtlCreateUserThread, used with the x86 executex64 stub.

; This function is in the form (where the param is a pointer to a WOW64CONTEXT):
;     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

;typedef struct _WOW64CONTEXT
;{
;  union
;  {
;    HANDLE hProcess;
;    BYTE bPadding2[8];
;  } h;
;  union
;  {
;    LPVOID lpStartAddress;
;    BYTE bPadding1[8]; 
;  } s;
;  union
;  {
;    LPVOID lpParameter;
;    BYTE bPadding2[8];
;  } p;
;  union
;  {
;    HANDLE hThread;
;    BYTE bPadding2[8];
;  } t;
;} WOW64CONTEXT, * LPWOW64CONTEXT;

[BITS 64]
[ORG 0]
  cld                    ; Clear the direction flag.
  mov rsi, rcx           ; RCX is a pointer to our WOW64CONTEXT parameter
  mov rdi, rsp           ; save RSP to RDI so we can restore it later, we do this as we are going to force alignment below...
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned (as we originate from a wow64 (x86) process we cant guarantee alignment)
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm"
start:                   ;
  pop rbp                ; Pop off the address of 'api_call' for calling later.
  ; setup the parameters for RtlCreateUserThread...
  xor r9, r9             ; StackZeroBits = 0
  push r9                ; ClientID = NULL
  lea rax, [rsi+24]      ; RAX is now a pointer to ctx->t.hThread
  push rax               ; ThreadHandle = &ctx->t.hThread
  push qword [rsi+16]    ; StartParameter = ctx->p.lpParameter
  push qword [rsi+8]     ; StartAddress = ctx->s.lpStartAddress
  push r9                ; StackCommit = NULL
  push r9                ; StackReserved = NULL
  mov r8, 1              ; CreateSuspended = TRUE
  xor rdx, rdx           ; SecurityDescriptor = NULL
  mov rcx, [rsi]         ; ProcessHandle = ctx->h.hProcess
  ; perform the call to RtlCreateUserThread...
  mov r10d, 0x40A438C8   ; hash( "ntdll.dll", "RtlCreateUserThread" ) 
  call rbp               ; RtlCreateUserThread( ctx->h.hProcess, NULL, TRUE, 0, NULL, NULL, ctx->s.lpStartAddress, ctx->p.lpParameter, &ctx->t.hThread, NULL )
  test rax, rax          ; check the NTSTATUS return value
  jz success             ; if its zero we have successfully created the thread so we should return TRUE
  mov rax, 0             ; otherwise we should return FALSE
  jmp cleanup            ;
success:
  mov rax, 1             ; return TRUE
cleanup:
  add rsp, (32 + (8*6))  ; fix up stack (32 bytes for the single call to api_call, and 6*8 bytes for the six params we pushed).
  mov rsp, rdi           ; restore the stack
  ret                    ; and return to caller
