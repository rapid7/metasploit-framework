##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meterpreter_x86_bsd'
require 'msf/base/sessions/meterpreter_options'

module MetasploitModule

  CachedSize = 0

  include Msf::Payload::Bsd
  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'FreeBSD Meterpreter Service, Bind TCP',
      'Description'   => 'Stub payload for interacting with a Meterpreter Service',
      'Author'        => 'hdm',
      'License'       => BSD_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::Meterpreter_x86_BSD,
      'Payload'       =>
        {
          'Offsets' => {},
          'Payload' => ""
        }
      ))
  end
end
