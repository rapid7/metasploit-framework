#####################################################################
# tc_device_io.rb
#
# Test case for the Windows::DeviceIO module.
#####################################################################
require 'windows/device_io'
require 'test/unit'

class DeviceIOFoo
   include Windows::DeviceIO
end

class TC_Windows_DeviceIO < Test::Unit::TestCase
   def setup
      @foo  = DeviceIOFoo.new
   end

   def test_numeric_constants
      assert_equal(0x00000001, DeviceIOFoo::FILE_DEVICE_BEEP)
   end

   def test_method_constants
      assert_not_nil(DeviceIOFoo::DeviceIoControl)
   end

   def teardown
      @foo  = nil
   end
end
