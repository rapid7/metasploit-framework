
##
# $Id: smb_login.rb 8121 2010-01-14 18:51:04Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Telnet
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'        => 'Telnet Login Check Scanner',
			#'Version'     => '$Revision: 8121 $',
			'Description' => %q{
				This module will test a telnet login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => 'egypt',
			'License'     => MSF_LICENSE
		)
		deregister_options('RHOST')
		register_options(
			[
				OptInt.new('ATTEMPTS', [ false, 'Number of login attempts before reconnecting', 3 ])
			], Msf::Exploit::Remote::Telnet)

		@attempts = 0
	end

	def run_host(ip)
		print_status("Starting host #{ip}")
		begin
			connect
			each_user_pass { |user, pass|
				try_user_pass(user, pass)
			}
			disconnect
		rescue ::Rex::ConnectionError
			return
		end
	end

	def try_user_pass(user, pass)
		@attempts += 1
		if @attempts % datastore["ATTEMPTS"] == 0
			disconnect	
			connect
		end
		send_user(user)
		if (send_pass(pass))
			print_good("#{rhost} - SUCCESSFUL LOGIN #{user} : #{pass}")
			report_auth_info(
				:host	=> rhost,
				:proto	=> 'telnet',
				:user	=> user,
				:pass	=> pass,
				:targ_host	=> rhost,
				:targ_port	=> datastore['RPORT']
			)
			ret = :next_user
		else
			ret = nil
		end

		disconnect()
		return nil
	end

end

