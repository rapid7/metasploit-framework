#!/usr/bin/ruby

require 'test/unit'
require 'Msf/Core'
require 'Msf/Core/OptionContainer.rb.ut'

class Msf::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new

		suite << Msf::OptionContainer::UnitTest.suite

		return suite;
	end
end
