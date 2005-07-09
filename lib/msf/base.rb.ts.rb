#!/usr/bin/ruby

require 'test/unit'
require 'msf/base'
require 'msf/base/session/command_shell.rb.ut'
require 'msf/base/session/meterpreter.rb.ut'
require 'msf/base/session/dispatch_ninja.rb.ut'
require 'msf/base/session/vnc.rb.ut'

module Msf
module Base

class TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Msf Base")

		suite << Msf::Session::CommandShell::UnitTest.suite
		suite << Msf::Session::Meterpreter::UnitTest.suite
		suite << Msf::Session::DispatchNinja::UnitTest.suite
		suite << Msf::Session::Vnc::UnitTest.suite

		return suite;
	end
end

end
end
