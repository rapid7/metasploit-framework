#!/usr/bin/ruby

require 'machinetestinternal'

module MachineTest
	def MachineTest.test(str, all = false)
		MachineTest::Internal.test(str + "\xcc", all)
	end
	def MachineTest.testraw(str, all = false)
		MachineTest::Internal.test(str, all)
	end
end
