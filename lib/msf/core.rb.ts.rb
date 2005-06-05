#!/usr/bin/ruby

require 'test/unit'
require 'Msf/Core'
require 'Msf/Core/Exceptions.rb.ut'
require 'Msf/Core/OptionContainer.rb.ut'
require 'Msf/Core/SessionManager.rb.ut'

require 'Msf/Core/Module/PlatformList.rb.ut'

require 'Msf/Core/Exploit.rb.ut'

class Msf::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Msf Core")

		suite << Msf::Exceptions::UnitTest.suite
		suite << Msf::OptionContainer::UnitTest.suite
		suite << Msf::SessionManager::UnitTest.suite

		suite << Msf::Module::PlatformList::UnitTest.suite

		suite << Msf::Exploit::UnitTest.suite

		return suite;
	end
end
