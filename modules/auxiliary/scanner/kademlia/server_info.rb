##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::Kademlia

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
    ])
  end

  def build_probe
    @probe ||= case action.name
               when 'BOOTSTRAP'
                 BootstrapRequest.new
               when 'PING'
                 Ping.new
               end
  end

  def scanner_process(response, src_host, src_port)
    return if response.blank?
    peer = "#{src_host}:#{src_port}"

    case action.name
    when 'BOOTSTRAP'
      if bootstrap_res = BootstrapResponse.from_data(response)
        info = {
          peer_id: bootstrap_res.peer_id,
          tcp_port: bootstrap_res.tcp_port,
          version: bootstrap_res.version,
          peers: bootstrap_res.peers
        }
        print_good("#{peer} ID #{bootstrap_res.peer_id}, TCP port #{bootstrap_res.tcp_port}," +
                   " version #{bootstrap_res.version}, #{bootstrap_res.peers.size} peers")
      end
    when 'PING'
      if pong = Pong.from_data(response)
        print_good("#{peer} PONG port #{pong.port}")
        # port should match the port we contacted it from.  TODO: validate this?
        info = { udp_port: pong.port }
      end
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
        name: 'kademlia',
        info: info
      )
    end
  end
end
