#####################################################################
# tc_shell.rb
#
# Test case for the Windows::Shell module.
#####################################################################
require 'windows/shell'
require 'test/unit'

class ShellFoo
   include Windows::Shell
end

class TC_Windows_Shell < Test::Unit::TestCase
   def setup
      @foo = ShellFoo.new
   end

   def test_numeric_constants
      assert_equal(0, ShellFoo::CSIDL_DESKTOP)
      assert_equal(1, ShellFoo::CSIDL_INTERNET)
      assert_equal(2, ShellFoo::CSIDL_PROGRAMS)
   end
   
   def test_method_constants
      assert_not_nil(ShellFoo::DragQueryFile)
      assert_not_nil(ShellFoo::ExtractIcon)
      assert_not_nil(ShellFoo::ExtractIconEx)
      assert_not_nil(ShellFoo::ShellAbout)
   end
   
   def teardown
      @foo = nil
   end
end
