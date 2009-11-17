##
# $Id: generic_sh.rb 6957 2009-08-17 17:42:39Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

	def initialize
		super(
			'Name'             => 'Generic ${IFS} Substitution Command Encoder',
			'Version'          => '$Revision: 6957 $',
			'Description'      => %q{
				This encoder uses standard Bourne shell variable substitution
				to avoid spaces without being overly fancy.
			},
			'Author'           => 'egypt',
			'Arch'             => ARCH_CMD)
	end

	
	#
	# Encodes the payload
	#
	def encode_block(state, buf)
		buf.gsub!(/\s/, '${IFS}')
		return buf
	end	

end
