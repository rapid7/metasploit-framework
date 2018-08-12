##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/empire'

module MetasploitModule

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Powershell Empire Windows',
        'Description' => 'Powershell Empire Windows',
        'Author'      => [
          'Brent Cook <bcook[at]rapid7.com>',
        ],
        'Platform'    => ['empire'],
        'Arch'        => ARCH_CMD,
        'License'     => MSF_LICENSE,
        'Session'     => Msf::Sessions::EmpireShellWindows
      )
    )
  end

  def generate_stage(opts = {})
  end
end
