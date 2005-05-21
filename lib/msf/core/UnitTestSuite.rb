require 'Msf/Core'

module Msf
module Test

###
#
# FrameworkCoreTestSuite
# ----------------------
#
# This test suite is used to test the various core components of
# framework-core.
#
###
class FrameworkCoreTestSuite
	def self.suite
		suite = ::Test::Unit::TestSuite.new

		suite << Msf::Test::OptionContainerTestCase.suite

		return suite;
	end
end

end
end
