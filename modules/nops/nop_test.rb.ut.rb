##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


#!/usr/bin/env ruby
#
# This file tests all x86 nops to ensure that they execute correctly.
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'dev', 'machinetest'))

require 'rex'
require 'msf/core'
require 'msf/base'
require 'machinetest'

$framework = Msf::Simple::Framework.create

$framework.nops.each_module { |name, mod|
	e = mod.new
	h = {}
	failed = 0
	passed = 0

	next if (e.arch?(ARCH_X86) == false)

	1000.times {

		if (off = MachineTest.test(buf = e.generate_sled(64), true))
			failed += 1
			$stderr.puts("#{name.ljust(25)}: failure at byte #{off}: #{Rex::Text.to_hex(buf)}")
		else
			passed += 1
		end

		h[buf] = true

	}

	$stderr.puts("#{name.ljust(25)}: Passed: #{passed}, Failed: #{failed}, Unique: #{h.keys.length}")

}
