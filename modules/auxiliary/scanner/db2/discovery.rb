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
      'Name'           => 'DB2 Discovery Service Detection',
      'Description'    => 'This module simply queries the DB2 discovery service for information.',
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE
    )

    register_options([Opt::RPORT(523),])

    deregister_options('RHOST')
  end

  def run_host(ip)

    pkt = "DB2GETADDR" + "\x00" + "SQL05000" + "\x00"

    begin

      connect_udp
      udp_sock.put(pkt)
      res = udp_sock.read(1024)

      unless res
        print_error("Unable to determine version info for #{ip}")
        return
      end

      res = res.split(/\x00/)

      report_note(
        :host   => ip,
        :proto  => 'udp',
        :port   => datastore['RPORT'],
        :type   => 'SERVICE_INFO',
        :data   => "#{res[2]}_#{res[1]}"
        )

      report_service(
        :host => ip,
        :port => datastore['RPORT'],
        :proto => 'udp',
        :name => "ibm-db2",
        :info => "#{res[2]}_#{res[1]}"
      )

      print_good("Host #{ip} node name is " + res[2] + " with a product id of " + res[1] )

    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE
    ensure
      disconnect_udp
    end

  end
end
