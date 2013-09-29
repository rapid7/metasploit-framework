##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::FindShell'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command, Interact with Established Connection',
      'Description'   => 'Interacts with a shell on an established socket connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd_interact',
      'RequiredCmd'   => 'generic',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

end
