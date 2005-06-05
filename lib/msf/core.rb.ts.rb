#!/usr/bin/ruby

require 'test/unit'
require 'Msf/Core'
require 'Msf/Core/Exceptions.rb.ut'
require 'Msf/Core/OptionContainer.rb.ut'
require 'Msf/Core/SessionManager.rb.ut'

require 'Msf/Core/Module/Author.rb.ut'
require 'Msf/Core/Module/PlatformList.rb.ut'
require 'Msf/Core/Module/Reference.rb.ut'
require 'Msf/Core/Module/Target.rb.ut'

require 'Msf/Core/Exploit.rb.ut'
require 'Msf/Core/Exploit/Remote/Tcp.rb.ut'
require 'Msf/Core/Exploit/Remote/DCERPC.rb.ut'

class Msf::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new("Msf Core")

		suite << Msf::Exceptions::UnitTest.suite
		suite << Msf::OptionContainer::UnitTest.suite
		suite << Msf::SessionManager::UnitTest.suite

		suite << Msf::Module::Author::UnitTest.suite
		suite << Msf::Module::PlatformList::UnitTest.suite
		suite << Msf::Module::Reference::UnitTest.suite
		suite << Msf::Module::Target::UnitTest.suite

		suite << Msf::Exploit::UnitTest.suite
		suite << Msf::Exploit::Remote::Tcp::UnitTest.suite
		suite << Msf::Exploit::Remote::DCERPC::UnitTest.suite

		return suite;
	end
end
