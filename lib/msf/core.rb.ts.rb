#!/usr/bin/ruby

require 'test/unit'
require 'msf/core'
require 'msf/core/exceptions.rb.ut'
require 'msf/core/option_container.rb.ut'
require 'msf/core/session_manager.rb.ut'

require 'msf/core/module/author.rb.ut'
require 'msf/core/module/platform_list.rb.ut'
require 'msf/core/module/reference.rb.ut'
require 'msf/core/module/target.rb.ut'

require 'msf/core/exploit.rb.ut'
require 'msf/core/exploit/remote/tcp.rb.ut'
require 'msf/core/exploit/remote/dcerpc.rb.ut'

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
