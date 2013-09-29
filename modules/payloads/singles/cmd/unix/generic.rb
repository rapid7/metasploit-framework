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

  handler module_name: 'Msf::Handler::None'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command, Generic Command Execution',
      'Description'   => 'Executes the supplied command',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'generic',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))

    register_options(
      [
        OptString.new('CMD', [ true, "The command string to execute" ]),
      ], self.class)
  end

  #
  # Constructs the payload
  #
  def generate
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    return datastore['CMD'] || ''
  end

end
