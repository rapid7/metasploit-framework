
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

	end

	def run_host(ip)
		print_status("Starting host #{ip}")
		if (datastore["SMBUser"] and not datastore["SMBUser"].empty?)
			# then just do this user/pass
			try_user_pass(datastore["SMBUser"], datastore["SMBPass"])
		else
			begin
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
			disconnect()
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
			# This gets spammy against default samba installs that accept just
			# about anything for a guest login
			print_status("#{rhost} - GUEST LOGIN (#{smb_peer_os}) #{user} : #{pass}")
		end

		disconnect()
		# If we get here then we've found the password for this user, move on
		# to the next one.
		return :next_user
	end

end

