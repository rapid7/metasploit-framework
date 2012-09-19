#####################################################################
# tc_window.rb
#
# Test case for the Windows::Window module.
#####################################################################
require 'windows/window'
require 'test/unit'

class WindowFoo
   include Windows::Window
end

class TC_Windows_Window < Test::Unit::TestCase
   def setup
      @foo = WindowFoo.new
   end

   def test_numeric_constants
      assert_equal(0, WindowFoo::SW_HIDE)
      assert_equal(1, WindowFoo::SW_SHOWNORMAL)
      assert_equal(1, WindowFoo::SW_NORMAL)
      assert_equal(2, WindowFoo::SW_SHOWMINIMIZED)
      assert_equal(3, WindowFoo::SW_SHOWMAXIMIZED)
      assert_equal(3, WindowFoo::SW_MAXIMIZE)
      assert_equal(4, WindowFoo::SW_SHOWNOACTIVATE)
      assert_equal(5, WindowFoo::SW_SHOW)
      assert_equal(6, WindowFoo::SW_MINIMIZE)
      assert_equal(7, WindowFoo::SW_SHOWMINNOACTIVE)
      assert_equal(8, WindowFoo::SW_SHOWNA)
      assert_equal(9, WindowFoo::SW_RESTORE)
      assert_equal(10, WindowFoo::SW_SHOWDEFAULT)
      assert_equal(11, WindowFoo::SW_FORCEMINIMIZE)
      assert_equal(11, WindowFoo::SW_MAX)
   end
   
   def test_method_constants
      assert_not_nil(WindowFoo::GetClientRect)
      assert_not_nil(WindowFoo::GetForegroundWindow)
      assert_not_nil(WindowFoo::GetWindowRect)
   end
   
   def teardown
      @foo = nil
   end
end
