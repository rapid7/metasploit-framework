##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meterpreter_x86_linux'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3

  include Msf::Payload::Linux
  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Meterpreter Service, Bind TCP',
      'Description'   => 'Stub payload for interacting with a Meterpreter Service',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::Meterpreter_x86_Linux,
      'Payload'       =>
        {
          'Offsets' => {},
          'Payload' => ""
        }
      ))
  end

end
