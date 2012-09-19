##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy. 
# I’d also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'SAP RFC RFC_READ_TABLE',
			'Version' => '$Revision: $0.1',
			'Description' => %q{
				This module makes use of the RFC_READ_TABLE Remote Function Call (via SOAP) to read data from tables.
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'Agnivesh Sathasivam & nmonkee' ],
			'License' => BSD_LICENSE
			)
	
	register_options(
		[
			OptString.new('RHOSTS', [true, 'SAP ICM server address', nil]),
			OptString.new('RPORT', [true, 'SAP ICM server port number', nil]),
			OptString.new('CLIENT', [true, 'Client', nil]),
			OptString.new('USER', [true, 'Username', nil]),
			OptString.new('PASS', [true, 'Password', nil]),
			OptString.new('TABLE', [true, 'Table to read', nil]),
			OptString.new('FIELDS', [true, 'Fields to read', '*']),
		], self.class)
	end
	
	def run_host(ip)
		columns = []
		columns.push ('*') if datastore['FIELDS'].nil?
		if datastore['FIELDS']
			columns.push (datastore['FIELDS']) if datastore['FIELDS'] =~ /^\w?/
			columns = datastore['FIELDS'].split(',') if datastore['FIELDS'] =~ /\w*,\w*/
		end
		fields = ''
		columns.each do |d|
			fields << "<item><FIELDNAME>" + d.gsub(/\s+/, "") + "</FIELDNAME></item>"
		end
		exec(fields)
	end
	
	def exec(fields)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
		data << '<env:Body>'
		data << '<n1:RFC_READ_TABLE xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<DELIMITER xsi:type="xsd:string">|</DELIMITER>'
		data << '<NO_DATA xsi:nil="true"></NO_DATA>'
		data << '<QUERY_TABLE xsi:type="xsd:string">' + datastore['TABLE'] + '</QUERY_TABLE>'
		data << '<DATA xsi:nil="true"></DATA>'
		data << '<FIELDS xsi:nil="true">' + fields + '</FIELDS>'
		data << '<OPTIONS xsi:nil="true"></OPTIONS>'
		data << '</n1:RFC_READ_TABLE>'
		data << '</env:Body>'
		data << '</env:Envelope>'
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		print_status("#{datastore['RHOSTS']}:#{datastore['RPORT']} - sending SOAP RFC_READ_TABLE request")
		begin
			error = ''
			success = ''
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
				if res.body =~ /<h1>Logon failed<\/h1>/
					print_error("#{rhost}:#{rport} - login failed!")
				else
					print_error("#{rhost}:#{rport} - something went wrong!")
				end
				return
			elsif res.body =~ /Exception/
				response = res.body
				error = response.scan(%r{<faultstring>(.*?)</faultstring>})
				success = false
				return
			else
				response = res.body
				success = true
			end
			if success == true
				output = response.scan(%r{<WA>([^<]+)</WA>}).flatten
				print_status("#{datastore['RHOSTS']}:#{datastore['RPORT']} - got response")
				saptbl = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
						'Header' => "[SAP] RFC_READ_TABLE",
						'Prefix' => "\n",
						'Postfix' => "\n",
						'Indent' => 1,
						'Columns' => ["Returned Data"],
						)
				for i in 0..output.length-1
					saptbl << [output[i]]
				end
				print(saptbl.to_s)
			end
			if success == false
				for i in 0..error.length-1
					print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} - error #{error[i]}")
				end
			end
			rescue ::Rex::ConnectionError
				print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} - Unable to connect")
				return
			end
		end
	end  