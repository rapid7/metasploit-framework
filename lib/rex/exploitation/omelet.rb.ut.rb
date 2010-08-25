# $Id$

require 'omelet.rb'

x = Rex::Exploitation::Omelet.new('win', ARCH_X86)
x.generate("\xcc" * 1024, '', {
	#:eggsize => 31336,       # default: 123
	#:eggtag => "b00",        # default: 00w
	#:searchforward => false, # default: true
	#:reset => true,          # default: false
	#:startreg => "EBP",      # default: none
	:checksum => true        # default: false
})
