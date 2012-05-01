#####################################################################
# tc_limits.rb
#
# Test case for the Windows::Limits module.
#####################################################################
require 'windows/limits'
require 'test/unit'

class LimitsFoo
   include Windows::Limits
end

class TC_Windows_Limits < Test::Unit::TestCase
  
   def setup
      @foo = LimitsFoo.new
   end

   def test_numeric_constants
      assert_equal(0x80, LimitsFoo::MINCHAR)
      assert_equal(0x7f, LimitsFoo::MAXCHAR)
      assert_equal(0x8000, LimitsFoo::MINSHORT)
      assert_equal(0x7fff, LimitsFoo::MAXSHORT)
      assert_equal(0x80000000, LimitsFoo::MINLONG)
      assert_equal(0x7fffffff, LimitsFoo::MAXLONG)
      assert_equal(0xff, LimitsFoo::MAXBYTE)
      assert_equal(0xffff, LimitsFoo::MAXWORD)
      assert_equal(0xffffffff, LimitsFoo::MAXDWORD)
   end
   
   def teardown
      @foo = nil
   end
end
