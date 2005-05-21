#!/usr/bin/ruby -I../Framework

require 'test/unit/ui/console/testrunner'
require 'Msf'

Test::Unit::UI::Console::TestRunner.run(Msf::Test::FrameworkCoreTestSuite)
