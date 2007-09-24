##
# $Id: simple.rb 4419 2007-02-18 00:10:39Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf
module Nops
module Armle

###
#
# SingleByte
# ----------
#
# This class implements simple NOP generator for ARM (little endian)
#
###
class Simple < Msf::Nop


	def initialize
		super(
			'Name'        => 'Simple',
			'Alias'       => 'armle_simple',
			'Version'     => '$Revision: 4419 $',
			'Description' => 'Simple NOP generator',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Arch'        => ARCH_ARMLE)

		register_advanced_options(
			[
				OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
			], self.class)
	end


	def generate_sled(length, opts)
		
		badchars = opts['BadChars'] || ''
		random   = opts['Random']   || datastore['RandomNops']

		nops = [ 
			0xe1a01001,
			0xe1a02002,
			0xe1a03003,
			0xe1a04004,
			0xe1a05005,
			0xe1a06006,
			0xe1a07007,
			0xe1a08008,
			0xe1a09009,
			0xe1a0a00a,
			0xe1a0b00b
		]
				
		if( random and random.match(/^(t|y|1)/i) )
			return ([nops[rand(nops.length)]].pack("V*") * (length/4))
		end

		return (nops[0].pack("V*") * (length/4))
	end

end

end end end
