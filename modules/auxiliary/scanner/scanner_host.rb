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

module Msf

class Auxiliary::Scanner::HostTest < Msf::Auxiliary

	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'Simple Recon Module Tester',
			'Version'     => '$Revision$',
			'Description' => 'Simple Recon Module Tester',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT,
			], self.class)	

	end

	def run_host(ip)
		print_status("Working on host #{ip}")
	end

	
end
end
