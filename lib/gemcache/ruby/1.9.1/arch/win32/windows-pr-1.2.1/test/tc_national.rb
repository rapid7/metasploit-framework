#####################################################################
# tc_national.rb
#
# Test case for the Windows::National module.
#####################################################################
require 'windows/national'
require 'test/unit'

class NationalFoo
   include Windows::National
end

class TC_Windows_National < Test::Unit::TestCase
   def setup
      @foo = NationalFoo.new
   end

   def test_numeric_constants
      assert_equal(2048, NationalFoo::LANG_SYSTEM_DEFAULT)
      assert_equal(1024, NationalFoo::LANG_USER_DEFAULT)
      assert_equal(2048, NationalFoo::LOCALE_SYSTEM_DEFAULT)
      assert_equal(1024, NationalFoo::LOCALE_USER_DEFAULT)
      assert_equal(8323072, NationalFoo::LOCALE_INVARIANT)
   end
   
   def test_method_constants
      assert_not_nil(NationalFoo::GetACP)
      assert_not_nil(NationalFoo::GetDateFormat)
      assert_not_nil(NationalFoo::GetLocaleInfo)
      assert_not_nil(NationalFoo::GetSystemDefaultLangID)
      assert_not_nil(NationalFoo::GetUserDefaultLangID)
      assert_not_nil(NationalFoo::GetUserDefaultLCID)
   end
   
   def teardown
      @foo = nil
   end
end
