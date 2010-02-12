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
        
	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	
	def initialize
		super(
			'Name'           => 'MSSQL Ping Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module simply queries the MSSQL instance for information.',
			'Author'         => 'MC',
			'License'        => MSF_LICENSE
		)
		
		deregister_options('RPORT', 'RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		
		begin
		
		info = mssql_ping(2)
		if (info['ServerName'])
			print_status("SQL Server information for #{ip}:")
			info.each_pair { |k,v|
				print_status("   #{k + (" " * (15-k.length))} = #{v}")
			}
			if info['tcp']
				report_mssql_service(ip,info)
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
