
##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB	
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	
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
		register_options(
			[	
				OptString.new('SMBPass', [ false, "SMB Password", '']),
				OptString.new('SMBUser', [ false, "SMB Username", 'Administrator']),
				OptString.new('SMBDomain', [ false, "SMB Domain", 'WORKGROUP']),
			], self.class)
	end

	def run_host(ip)

		connect()
		
		begin
			smb_login()
		rescue Rex::Proto::SMB::Exceptions::LoginError => e
			if(e.error_code)
				print_status("#{ip} - FAILED #{ "0x%.8x" % e.error_code } - #{e.error_reason}")			
			else
				print_status("#{ip} - FAILED #{e}")
			end
			return
		end

		if(simple.client.auth_user)
			print_status("#{ip} - SUCCESSFUL LOGIN (#{smb_peer_os})")
			report_auth_info(
				:host	=> ip,
				:proto	=> 'SMB',
				:user	=> datastore['SMBUser'],
				:pass	=> datastore['SMBPass'],
				:targ_host	=> ip,
				:targ_port	=> datastore['RPORT']
			)
		else 
			print_status("#{ip} - GUEST LOGIN (#{smb_peer_os})")
		end

		disconnect()
	end
end

