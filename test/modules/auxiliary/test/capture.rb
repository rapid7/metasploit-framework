##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'        => 'Simple Network Capture Tester',
      'Description' => 'This module sniffs HTTP GET requests from the network',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Sniffer' ]
        ],
      'PassiveActions' =>
        [
          'Sniffer'
        ],
      'DefaultAction'  => 'Sniffer'
    )

    deregister_options('RHOST')
  end

  def run
    print_status("Opening the network interface...")
    open_pcap()

    print_status("Sniffing HTTP requests...")
    each_packet() do |pkt|
      p = PacketFu::Packet.parse(pkt)
      next unless p.is_tcp?
      next if p.payload.empty?
      if (p.payload =~ /GET\s+([^\s]+)\s+HTTP/smi)
        url = $1
        print_status("GET #{url}")
        break if url =~ /StopCapture/
      end

    end
    close_pcap()
    print_status("Finished sniffing")
  end

end

