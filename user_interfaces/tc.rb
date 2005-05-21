#!/usr/bin/ruby -I../Lib

require 'test/unit/ui/console/testrunner'
require 'Msf/Core'

Test::Unit::UI::Console::TestRunner.run(Msf::Test::FrameworkCoreTestSuite)
