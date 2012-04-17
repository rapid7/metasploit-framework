#####################################################################
# tc_window_menu.rb
#
# Test case for the Windows::Window::Menu module.
#####################################################################
require 'windows/window/menu'
require 'test/unit'

class WindowMenuFoo
   include Windows::Window::Menu
end

class TC_Windows_Window_Menu < Test::Unit::TestCase
   def setup
      @foo = WindowMenuFoo.new
   end

   def test_numeric_constants
      assert_equal(0, WindowMenuFoo::MF_INSERT)
   end
   
   def test_method_constants
      assert_not_nil(WindowMenuFoo::AppendMenu)
   end
   
   def teardown
      @foo = nil
   end
end
