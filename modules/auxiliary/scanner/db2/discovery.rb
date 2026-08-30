##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Udp

  def initialize
    super(
      'Name' => 'DB2 Discovery Service Detection',
      'Description' => 'This module simply queries the DB2 discovery service for information.',
      'Author' => [ 'MC' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([Opt::RPORT(523),])
  end

  def run_host(ip)
    pkt = 'DB2GETADDR' + "\x00" + 'SQL05000' + "\x00"

    connect_udp
    udp_sock.put(pkt)
    res = udp_sock.read(1024)

    unless res
      print_error("Unable to determine version info for #{ip}")
      return
    end

    res = res.split(/\x00/)

    product_id = res[1]
    node_name = res[2]

    report_note(
      host: ip,
      proto: 'udp',
      port: datastore['RPORT'],
      type: 'SERVICE_INFO',
      data: { service_info: "#{node_name}_#{product_id}" }
    )

    report_service(
      host: ip,
      port: datastore['RPORT'],
      proto: 'udp',
      name: 'ibm-db2',
      info: "#{node_name}_#{product_id}"
    )

    print_good("Host #{ip} node name is #{node_name} with a product id of #{product_id}")
  rescue ::Rex::ConnectionError => e
    vprint_error(e.message)
  rescue ::Errno::EPIPE => e
    vprint_error(e.message)
  ensure
    disconnect_udp
  end
end
