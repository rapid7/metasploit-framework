##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Meterpreter Service, Bind TCP',
      'Description'   => 'Stub payload for interacting with a Meterpreter Service',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::Meterpreter_x86_Win,
      'Payload'       =>
        {
          'Offsets' => {},
          'Payload' => ""
        }
      ))
  end

end
