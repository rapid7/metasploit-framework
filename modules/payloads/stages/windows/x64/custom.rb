##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Custom
  include Msf::Payload::Custom::Options

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows shellcode stage',
        'Description' => 'Custom shellcode stage',
        'Author' => 'bwatters-r7',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64,
        'Session' => Msf::Sessions::Custom,
        'PayloadCompat' => {}
      )
    )
  end
end
