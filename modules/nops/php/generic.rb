require 'msf/core'

module Msf
module Nops
module Php

###
#
# This class implements a "nop" generator for PHP payloads
#
###
class Generic < Msf::Nop

	def initialize
		super(
			'Name'        => 'PHP Nop Generator',
			'Alias'       => 'php_generic',
			'Version'     => '$Revision: 3425 $',
			'Description' => 'Generates harmless padding for PHP scripts',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Arch'        => ARCH_PHP)
	end

	# Generate valid PHP code up to the requested length
	def generate_sled(length, opts = {})
		# Default to just spaces for now
		" " * length
	end

end

end end end
