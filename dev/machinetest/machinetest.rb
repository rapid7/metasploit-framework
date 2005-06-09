#!/usr/bin/ruby

require 'machinetestinternal'

module MachineTest
	def MachineTest.test(str, all = false)
		MachineTest::Internal.test(str + "\xcc", all)
	end
end
