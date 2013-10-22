##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'        => 'Simple Ethernet Frame Spoofer',
      'Version'     => '$Revision$',
      'Description' => 'This module sends spoofed ethernet frames',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Spoofer' ]
        ],
      'DefaultAction'  => 'Spoofer'
    )
  end

  def run
    print_status("Opening the network interface...")
    open_pcap()

    p = PacketFu::UDPPacket.new
    p.eth_saddr = "00:41:41:41:41:41"
    p.eth_daddr = "00:42:42:42:42:42"
    p.ip_saddr = "41.41.41.41"
    p.ip_daddr = "42.42.42.42"
    p.udp_sport = 0x41
    p.udp_dport = 0x42
    p.payload = "SPOOOOOFED"
    p.recalc
    1.upto(10) do
      capture.inject(p.to_s)
    end

    close_pcap()
    print_status("Finished sending")
  end

end
