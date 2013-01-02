##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Oracle XML DB SID Discovery',
			'Description' => %q{
					This module simply makes a authenticated request to retrieve
					the sid from the Oracle XML DB httpd server.
			},
			'References'  =>
				[
					[ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
				],
			'Author'      => [ 'MC' ],
			'License'     => MSF_LICENSE
		)

		register_options(
				[
					Opt::RPORT(8080),
					OptString.new('DBUSER', [ false, 'The db user to authenticate with.',  'scott']),
					OptString.new('DBPASS', [ false, 'The db pass to authenticate with.',  'tiger']),
				], self.class)
	end

	def run_host(ip)
		begin

			user_pass = "#{datastore['DBUSER']}:#{datastore['DBPASS']}"

			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/GLOBAL_NAME',
				'version' => '1.0',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, 5)

				if( not res )
					vprint_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
					return
				end

				if (res.code == 200)
					if (not res.body.length > 0)
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end
					sid = res.body.scan(/<GLOBAL_NAME>(\S+)<\/GLOBAL_NAME>/)
						report_note(
							:host	=> ip,
							:port => datastore['RPORT'],
							:proto	=> 'tcp',
							:type	=> 'oracle_sid',
							:data	=> sid,
							:update => :unique_data
						)
					print_status("Discovered SID: '#{sid}' for host #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}")
				else
					print_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
				end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
