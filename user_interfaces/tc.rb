#!/usr/bin/ruby -I../Lib

require 'test/unit/ui/console/testrunner'
require 'Msf/Core.rb.ts'
require 'Msf/Base.rb.ts'

Test::Unit::UI::Console::TestRunner.run(Msf::TestSuite)
Test::Unit::UI::Console::TestRunner.run(Msf::Base::TestSuite)
