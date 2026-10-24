##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::WindowsOptions
  include Msf::Payload::Adapter::Fetch::FTP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FTP Fetch',
        'Description' => 'Fetch and execute an AARCH64 payload from an FTP server.',
        'Author' => 'Brendan Watters',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_AARCH64,
        'AdaptedPlatform' => 'win'
      )
    )
  end
end
