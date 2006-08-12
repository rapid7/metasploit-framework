require 'msf/core'

module Msf

class Auxiliary::ScannerBatchTest < Msf::Auxiliary

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

	def run_batch_size
		3
	end
	
	def run_batch(batch)
		print_status("Working on batch #{batch.join(",")}")
	end
	
end
end
