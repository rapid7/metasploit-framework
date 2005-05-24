#!/usr/bin/ruby -I../Lib

require 'test/unit/ui/console/testrunner'
require 'Msf/Core.rb.ts'

Test::Unit::UI::Console::TestRunner.run(Msf::TestSuite)
