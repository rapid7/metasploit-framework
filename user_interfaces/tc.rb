#!/usr/bin/ruby -I../Lib

require 'test/unit/ui/console/testrunner'
require 'rex.rb.ts'
require 'msf/core.rb.ts'
require 'msf/base.rb.ts'

Test::Unit::UI::Console::TestRunner.run(Rex::TestSuite)
Test::Unit::UI::Console::TestRunner.run(Msf::TestSuite)
Test::Unit::UI::Console::TestRunner.run(Msf::Base::TestSuite)
