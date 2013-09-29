##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/find_tty'
require 'msf/base/sessions/command_shell'


module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single

  handler module_name: 'Msf::Handler::FindTty'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix TTY, Interact with Established Connection',
      'Description'   => 'Interacts with a TTY on an established socket connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_TTY,
      'Session'       => Msf::Sessions::TTY,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

end
