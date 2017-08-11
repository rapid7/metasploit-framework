##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/generic'
require 'msf/core/handler/bind_tcp'

module MetasploitModule

  CachedSize = 0

  include Msf::Payload::Single
  include Msf::Payload::Generic

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Generic Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell
      ))
  end
end
