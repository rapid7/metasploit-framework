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
							for VMWare Server, ESX, and ESXi',
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

		return unless check(ip)

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
					:proto  => 'tcp',
					:sname  => 'https',
					:source_type => "user_supplied",
					:active => true
				)
				return if datastore['STOP_ON_SUCCESS']
			when :fail
				print_error "#{ip}:#{rport} - Login Failure (#{user}:#{pass})"
			end
		}
	end

	# Mostly taken from the Apache Tomcat service validator
	def check(ip)
		datastore['URI'] ||= "/sdk"
		user = Rex::Text.rand_text_alpha(8)
		pass = Rex::Text.rand_text_alpha(8)
		begin
			res = send_request_cgi({
				'uri'     => datastore['URI'],
				'method'  => 'POST',
				'agent'   => 'VMware VI Client',
				'data' => gen_soap_data(user,pass)
			}, 25)
			if res
				fp = http_fingerprint({ :response => res })
				if fp =~ /VMWare/
					return true
				else
					vprint_error("http://#{ip}:#{rport} - Could not identify as VMWare")
					return false
				end
			else
				vprint_error("http://#{ip}:#{rport} - No response")
			end
		rescue ::Rex::ConnectionError => e
			vprint_error("http://#{ip}:#{rport}#{datastore['URI']} - #{e}")
			return false
		rescue
			vprint_error("Skipping #{ip} due to error - #{e}")
			return false
		end
	end

	def gen_soap_data(user,pass)
		soap_data = []
		soap_data << '<SOAP-ENV:Envelope SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">'
		soap_data << '    <SOAP-ENV:Body>'
		soap_data << '        <Login xmlns="urn:vim25">'
		soap_data << '            <_this type="SessionManager">ha-sessionmgr</_this>'
		soap_data << '            <userName>' + user.to_s + '</userName>'
		soap_data << '            <password>' + pass.to_s + '</password>'
		soap_data << '        </Login>'
		soap_data << '    </SOAP-ENV:Body>'
		soap_data << '</SOAP-ENV:Envelope>'
		soap_data.join
	end

	def do_login(user, pass)
		res = send_request_cgi({
			'uri'     => '/sdk',
			'method'  => 'POST',
			'agent'   => 'VMware VI Client',
			'data' => gen_soap_data(user,pass)
		}, 25)
		if res.code == 200
			return :success
		else
			return :fail
		end
	end

end

