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
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
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
    return if response.blank?
    peer = "#{src_host}:#{src_port}"

    case action.name
    when 'BOOTSTRAP'
      peer_id, tcp_port, version, peers = decode_bootstrap_res(response)
      info = {
        peer_id: peer_id,
        tcp_port: tcp_port,
        version: version,
        peers: peers
      }
      if datastore['VERBOSE']
      else
        print_good("#{peer} ID #{peer_id}, TCP port #{tcp_port}, version #{version}, #{peers.size} peers")
      end
    when 'PING'
      udp_port = decode_pong(response)
      print_good("#{peer} PONG")
      # udp_port should match the port we contacted it from.  TODO: validate this?
      info = { udp_port: udp_port }
    end

    return unless info
    @results[src_host] ||= []
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
