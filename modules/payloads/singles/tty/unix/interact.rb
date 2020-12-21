##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/find_tty'
require 'msf/base/sessions/command_shell'


module MetasploitModule

  CachedSize = 0

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix TTY, Interact with Established Connection',
      'Description'   => 'Interacts with a TTY on an established socket connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_TTY,
      'Handler'       => Msf::Handler::FindTty,
      'Session'       => Msf::Sessions::TTY,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end
end
