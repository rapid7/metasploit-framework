#####################################################################
# tc_com.rb
#
# Test case for the Windows::COM module.
#####################################################################
require "windows/com"
require "test/unit"

class TC_Windows_COM < Test::Unit::TestCase
   include Windows::COM

   def test_method_constants
      assert_respond_to(self, :BindMoniker)
      assert_respond_to(self, :CLSIDFromProgID)
      assert_respond_to(self, :CLSIDFromProgIDEx)
      assert_respond_to(self, :CoAddRefServerProcess)
      assert_respond_to(self, :CoAllowSetForegroundWindow)
      assert_respond_to(self, :CoCancelCall)
      assert_respond_to(self, :CoCopyProxy)
      assert_respond_to(self, :CoCreateFreeThreadedMarshaler)
      assert_respond_to(self, :CoCreateGuid)
      assert_respond_to(self, :CoCreateInstance)
   end

   def test_numeric_constants
      assert_equal(0, VT_EMPTY)
      assert_equal(1, VT_NULL)
      assert_equal(2, VT_I2)
      assert_equal(3, VT_I4)
      assert_equal(4, VT_R4)
   end
end
