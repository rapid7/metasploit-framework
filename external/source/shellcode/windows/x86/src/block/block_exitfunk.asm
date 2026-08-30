;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (24 July 2009)
; Size: 31 bytes
;-----------------------------------------------------------------------------;
; kernel32.dll!SetUnhandledExceptionFilter (0xEA320EFE) - This exit function
; will let the UnhandledExceptionFilter function perform its default handling
; routine. 
;
; kernel32.dll!ExitProcess (0x56A2B5F0) - This exit function will force the 
; process to terminate.
;
; kernel32.dll!ExitThread (0x0A2A1DE0) - This exit function will force the 
; current thread to terminate. On Windows 2008, Vista and 7 this function is
; a forwarded export to ntdll.dll!RtlExitUserThread and as such cannot be 
; called by the api_call function.
;
; ntdll.dll!RtlExitUserThread (0x6F721347) - This exit function will force 
; the current thread to terminate. This function is not available on Windows 
; NT or 2000.
;-----------------------------------------------------------------------------;
; Windows 7               6.1  
; Windows Server 2008 R2  6.1   If the EXITFUNK is ExitThread we must call
; Windows Server 2008     6.0   RtlExitUserThread instead.
; Windows Vista           6.0 _______________________________________________
; Windows Server 2003 R2  5.2
; Windows Server 2003     5.2
; Windows XP              5.1
; Windows 2000            5.0
; Windows NT4             4.0
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP must be the address of 'api_call'.
; Output: None.
; Clobbers: EAX, EBX, (ESP will also be modified)
; Note: Execution is not expected to (successfully) continue past this block

exitfunk:
  mov ebx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
  push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
  call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
  cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
  jl short goodbye       ; Then just call the exit function...
  cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
  jne short goodbye      ;
  mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
goodbye:                 ; We now perform the actual call to the exit function
  push byte 0            ; push the exit function parameter
  push ebx               ; push the hash of the exit function
  call ebp               ; call EXITFUNK( 0 );
