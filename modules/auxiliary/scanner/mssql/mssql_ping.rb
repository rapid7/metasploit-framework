##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'MSSQL Ping Utility',
      'Description'    => 'This module simply queries the MSSQL instance for information.',
      'Author'         => 'MC',
      'License'        => MSF_LICENSE
    )

    deregister_options('RPORT', 'RHOST')
  end

  def run_host(ip)

    begin

    info = mssql_ping(2)
    #print_status info.inspect
    if info and not info.empty?
      info.each do |instance|
        if (instance['ServerName'])
          print_status("SQL Server information for #{ip}:")
          instance.each_pair {|k,v| print_good("   #{k + (" " * (15-k.length))} = #{v}")}
          if instance['tcp']
            report_mssql_service(ip,instance)
          end
        end
      end
    end

    rescue ::Rex::ConnectionError
    end
  end

  def test_connection(ip,port)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port
      )
    rescue Rex::ConnectionError
      return :down
    end
    sock.close
    return :up
  end

  def report_mssql_service(ip,info)
    mssql_info = "Version: %s, ServerName: %s, InstanceName: %s, Clustered: %s" % [
      info['Version'],
      info['ServerName'],
      info['InstanceName'],
      info['IsClustered']
    ]
    report_service(
      :host => ip,
      :port => 1434,
      :name => "mssql-m",
      :proto => "udp",
      :info => "TCP: #{info['tcp']}, Servername: #{info['ServerName']}"
    )
    mssql_tcp_state = (test_connection(ip,info['tcp']) == :up ? "open" : "closed")
    report_service(
      :host => ip,
      :port => info['tcp'],
      :name => "mssql",
      :info => mssql_info,
      :state => mssql_tcp_state
    )

  end
end
