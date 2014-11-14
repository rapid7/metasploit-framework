##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/kademlia'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Rex::Proto::Kademlia

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Gather Kademlia Server Information',
        'Description'    => %q(
          This module uses the Kademlia BOOTSTRAP and PING messages to identify
          and extract information from Kademlia speaking UDP endpoints,
          typically belonging to eMule/eDonkey/BitTorrent servers or other P2P
          applications.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com',
        'References'     =>
          [
            # There are lots of academic papers on the protocol but they tend to lack usable
            # protocol details.  This is the best I've found
            ['URL', 'http://gbmaster.wordpress.com/2013/06/16/botnets-surrounding-us-sending-kademlia2_bootstrap_req-kademlia2_hello_req-and-their-strict-cousins/#more-125']
          ],
        'License'        => MSF_LICENSE,
        'Actions'        => [
          ['BOOTSTRAP', 'Description' => 'Use a Kademlia2 BOOTSTRAP'],
          ['PING', 'Description' => 'Use a Kademlia2 PING']
        ],
        'DefaultAction'  => 'BOOTSTRAP'
      )
    )

    register_options(
    [
      Opt::RPORT(4672)
    ], self.class)
  end

  def build_probe
    @probe ||= case action.name
               when 'BOOTSTRAP'
                 bootstrap
               when 'PING'
                 ping
               end
  end

  def scanner_process(response, src_host, src_port)
    info = message_decode(response)
    return unless info
    @results[src_host] ||= []
    if datastore['VERBOSE']
      print_good("#{src_host}:#{src_port} found '#{info.inspect}'")
    else
      print_good("#{src_host}:#{src_port} found '#{info[:name]}'")
    end
    @results[src_host] << info
  end

  def scanner_postscan(_batch)
    @results.each_pair do |host, info|
      report_host(host: host)
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'Kademlia',
        info: info
      )
    end
  end
end
