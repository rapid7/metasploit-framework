#####################################################################
# tc_window_message.rb
#
# Test case for the Windows::Window::Message module.
#####################################################################
require 'windows/window/message'
require 'test/unit'

class WindowMessageFoo
   include Windows::Window::Message
end

class TC_Windows_Window_Message < Test::Unit::TestCase
   def setup
      @foo = WindowMessageFoo.new
   end

   def test_numeric_constants
      assert_equal(5, WindowMessageFoo::WM_SIZE)
   end
   
   def test_method_constants
      assert_not_nil(WindowMessageFoo::PostMessage)
   end

   def test_method_mixin
      assert_respond_to(@foo, :PostMessage)
   end
   
   def teardown
      @foo = nil
   end
end
