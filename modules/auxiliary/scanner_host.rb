require 'msf/core'

module Msf

class Auxiliary::ScannerHostTest < Msf::Auxiliary

	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'Simple Recon Module Tester',
			'Version'     => '$Revision: 3624 $',
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
