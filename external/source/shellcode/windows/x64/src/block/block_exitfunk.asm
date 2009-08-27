;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2003
; Architecture: x64
;-----------------------------------------------------------------------------;

[BITS 64]

exitfunk:
  mov ebx, 0x0A2A1DE0   ; The EXITFUNK as specified by user...
  mov r10d, 0x9DBD95A6  ; hash( "kernel32.dll", "GetVersion" )
  call rbp              ; GetVersion(); (AL will = major version and AH will = minor version)
  add rsp, 40           ; cleanup the default param space on stack
  cmp al, byte 6        ; If we are not running on Windows Vista, 2008 or 7
  jl short goodbye      ; Then just call the exit function...
  cmp bl, 0xE0          ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
  jne short goodbye     ;
  mov ebx, 0x6F721347   ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
goodbye:                ; We now perform the actual call to the exit function
  push byte 0           ;
  pop rcx               ; set the exit function parameter
  mov r10d, ebx         ; place the correct EXITFUNK into r10d
  call rbp              ; call EXITFUNK( 0 );