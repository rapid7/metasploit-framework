#####################################################################
# tc_handle.rb
#
# Test case for the Windows::Handle module.
#####################################################################
require 'windows/handle'
require 'test/unit'

class HandleFoo
   include Windows::Handle
end

class TC_Windows_Handle < Test::Unit::TestCase
  
   def setup
      @foo = HandleFoo.new
   end

   def test_numeric_constants
      assert_equal(0xFFFFFFFF, HandleFoo::INVALID_HANDLE_VALUE)
      assert_equal(0x00000001, HandleFoo::HANDLE_FLAG_INHERIT)
      assert_equal(0x00000002, HandleFoo::HANDLE_FLAG_PROTECT_FROM_CLOSE)
   end
   
   def test_method_constants
      assert_not_nil(HandleFoo::CloseHandle)
      assert_not_nil(HandleFoo::DuplicateHandle)
      assert_not_nil(HandleFoo::GetHandleInformation)
      assert_not_nil(HandleFoo::Get_osfhandle)
      assert_not_nil(HandleFoo::Open_osfhandle)
   end
   
   def teardown
      @foo = nil
   end
end
