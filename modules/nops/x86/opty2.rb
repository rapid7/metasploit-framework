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
require 'rex/nop/opty2'

module Msf
module Nops
module X86

###
#
# Opty2
# -----
#
# This class implements single-byte NOP generation for X86.  It takes from
# ADMmutate and from spoonfu.
#
###
class Opty2 < Msf::Nop

	def initialize
		super(
			'Name'        => 'Opty2',
			'Version'     => '$Revision$',
			'Description' => 'Opty2 multi-byte NOP generator',
			'Author'      => [ 'spoonm', 'optyx' ],
			'License'     => MSF_LICENSE,
			'Arch'        => ARCH_X86)
	end

	def generate_sled(length, opts = {})
		opty = Rex::Nop::Opty2.new(
			opts['BadChars'] || '',
			opts['SaveRegisters'])

		opty.generate_sled(length)
	end

end

end end end
