
##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	
	def initialize
		super(
			'Name'        => 'SMB Login Check Scanner',
			#'Version'     => '$Revision: 5640 $',
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
		register_options(
			[	
				OptString.new('SMBPass', [ false, "SMB Password", '']),
				OptString.new('SMBUser', [ false, "SMB Username", 'Administrator']),
			], self.class)
	end

	def run_host(ip)
		print_status("Trying to login to #{ip}...")
		connect()	
		if simple.login(datastore['SMBName'], datastore['SMBUser'], datastore['SMBPass'], datastore['SMBDomain'])
			print_status("Login successful on #{ip}")
			report_auth_info(
				:host	=> ip,
				:proto	=> 'SMB',
				:user	=> datastore['SMBUser'],
				:pass	=> datastore['SMBPass'],
				:targ_host	=> ip,
				:targ_port	=> datastore['RPORT']
			)
		end
		disconnect()
	end
end

