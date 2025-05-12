##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Windows::EncryptedPayloadOpts
  include Msf::Sessions::CommandShellOptions

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
        'Arch' => ARCH_X86,
        'Session' => Msf::Sessions::EncryptedShell,
        'Dependencies' => [ Metasploit::Framework::Compiler::Mingw::X86 ],
        'PayloadCompat' => { 'Convention' => 'sockedi' }
      )
    )
  end
end
