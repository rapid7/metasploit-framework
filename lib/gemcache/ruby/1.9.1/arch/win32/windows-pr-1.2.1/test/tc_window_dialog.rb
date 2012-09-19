#####################################################################
# tc_window_dialog.rb
#
# Test case for the Windows::Window::Dialog module.
#####################################################################
require 'windows/window/dialog'
require 'test/unit'

class WindowDialogFoo
   include Windows::Window::Dialog
end

class TC_Windows_Window_Dialog < Test::Unit::TestCase
   def setup
      @foo = WindowDialogFoo.new
   end

   def test_numeric_constants
      assert_equal(0, WindowDialogFoo::MB_OK)
   end
   
   def test_method_constants
      assert_not_nil(WindowDialogFoo::MessageBox)
   end

   def test_method_mixin
      assert_respond_to(@foo, :MessageBox)
   end
   
   def teardown
      @foo = nil
   end
end
