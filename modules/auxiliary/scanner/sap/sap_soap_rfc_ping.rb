##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy. 
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name' => 'SAP SOAP RFC_PING',
			'Version' => '$Revision$',
			'Description' => %q{ 
				Calls the RFC_PING RFC module via SOAP to test the availability of the function.
				The function simply tests connectivity to remote RFC destinations.
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'Agnivesh Sathasivam and nmonkee' ],
			'License' => BSD_LICENSE
			)
		
		register_options(
			[
				OptString.new('RHOSTS', [true, 'SAP ICM server address', nil]),
				OptString.new('RPORT', [true, 'SAP ICM port number', nil]),
				OptString.new('CLIENT', [true, 'Client', nil]),
				OptString.new('USERNAME', [true, 'Username ', 'SAP*']),
				OptString.new('PASSWORD', [true, 'Password ', '06071992']),
			], self.class)
		register_autofilter_ports([ 8000 ])
	end

	def run_host(ip)
		exec()
	end

	def exec()
		client = datastore['CLIENT']	
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
		data << '<env:Body>'
		data << '<n1:RFC_PING xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '</n1:RFC_PING>'
		data << '</env:Body>'
		data << '</env:Envelope>'
		user_pass = Rex::Text.encode_base64(datastore['USERNAME'] + ":" + datastore['PASSWORD'])
		print_status("#{rhost}:#{rport} - sending SOAP RFC_PING request")
		begin
			res = send_request_raw({
				'uri' => '/sap/bc/soap/rfc?sap-client=' + client + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'headers' =>
					{
						'Content-Length' => data.size.to_s,
						'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
						'Cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + client,
						'Authorization'  => 'Basic ' + user_pass,
						'Content-Type'   => 'text/xml; charset=UTF-8',
					}
				}, 45)
			if (res.code != 500 and res.code != 200)
				# to do - implement error handlers for each status code, 404, 301, etc.
				if res.body =~ /<h1>Logon failed<\/h1>/
					print_error("#{rhost}:#{rport} - login failed!")
				else
					print_error("#{rhost}:#{rport} - something went wrong!")
				end
				return
			elsif res.body =~ /Response/
				print_status("#{rhost}:#{rport} - RFC service is alive")
			else
				print_status("#{rhost}:#{rport} - RFC service is not alive")
			end
			rescue ::Rex::ConnectionError
				print_error("#{rhost}:#{rport} - Unable to connect")
				return
			end
		end
	end