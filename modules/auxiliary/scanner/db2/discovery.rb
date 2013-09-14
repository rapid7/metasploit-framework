##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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

    register_options([Opt::RPORT(523),], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)

    pkt = "DB2GETADDR" + "\x00" + "SQL05000" + "\x00"

    begin

      connect_udp

      udp_sock.put(pkt)

      res = udp_sock.read(1024).split(/\x00/)

      if (res)
        report_note(
          :host   => ip,
          :proto  => 'udp',
          :port   => datastore['RPORT'],
          :type   => 'SERVICE_INFO',
          :data   => res[2] + "_" + res[1]
          )
        report_service(
          :host => ip,
          :port => datastore['RPORT'],
          :proto => 'udp',
          :name => "ibm-db2",
          :info => res[2] + "_" + res[1]
          )
        print_status("Host #{ip} node name is " + res[2] + " with a product id of " + res[1] )
      else
        print_error("Unable to determine version info for #{ip}")
      end

      disconnect_udp

    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE

    end

  end
end
