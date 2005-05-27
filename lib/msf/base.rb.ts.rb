#!/usr/bin/ruby

require 'test/unit'
require 'Msf/Base'
require 'Msf/Base/Session/CommandShell.rb.ut'
require 'Msf/Base/Session/Meterpreter.rb.ut'
require 'Msf/Base/Session/DispatchNinja.rb.ut'
require 'Msf/Base/Session/Vnc.rb.ut'

module Msf
module Base

class TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new

		suite << Msf::Session::CommandShell::UnitTest.suite
		suite << Msf::Session::Meterpreter::UnitTest.suite
		suite << Msf::Session::DispatchNinja::UnitTest.suite
		suite << Msf::Session::Vnc::UnitTest.suite

		return suite;
	end
end

end
end
