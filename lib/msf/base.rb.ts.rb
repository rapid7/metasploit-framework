#!/usr/bin/env ruby

require 'test/unit'
require 'msf/base'
require 'msf/base/sessions/command_shell.rb.ut'

module Msf
module Base

class TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Msf Base")

		suite << Msf::Session::CommandShell::UnitTest.suite

		return suite;
	end
end

end
end