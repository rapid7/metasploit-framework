#####################################################################
# tc_time.rb
#
# Test case for the Windows::Time module.
#####################################################################
require 'windows/time'
require 'test/unit'

class TimeFoo
   include Windows::Time
end

class TC_Windows_Time < Test::Unit::TestCase
   def setup
      @foo = TimeFoo.new
   end

   def test_numeric_constants
      assert_equal(0, TimeFoo::TIME_ZONE_ID_UNKNOWN)
      assert_equal(1, TimeFoo::TIME_ZONE_ID_STANDARD)
      assert_equal(2, TimeFoo::TIME_ZONE_ID_DAYLIGHT)
   end
   
   def test_method_constants
      assert_not_nil(TimeFoo::CompareFileTime)
      assert_not_nil(TimeFoo::GetLocalTime)
   end
   
   def teardown
      @foo = nil
   end
end
