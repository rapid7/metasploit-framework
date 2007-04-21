##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


#!/usr/bin/env ruby
#
# This file tests all x86 encoders to ensure that they execute correctly.
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'dev', 'machinetest'))

require 'rex'
require 'msf/core'
require 'msf/base'
require 'machinetest'

$framework = Msf::Simple::Framework.create

$framework.encoders.each_module { |name, mod|
	e = mod.new
	h = {}
	failed = 0
	passed = 0

	next if (e.arch?(ARCH_X86) == false)

	1000.times {

		if (rv = MachineTest.testraw(buf = e.to_native(e.encode("\xcc"))))
			failed += 1
			$stderr.puts("#{name.ljust(25)}[off=#{rv}]: failure: #{Rex::Text.to_hex(buf)}")
		else
			passed += 1
		end

		h[buf] = true

	}

	$stderr.puts("#{name.ljust(25)}: Passed: #{passed}, Failed: #{failed}, Unique: #{h.keys.length}")

}
