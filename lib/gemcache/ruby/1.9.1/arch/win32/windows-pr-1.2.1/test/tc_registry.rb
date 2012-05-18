#####################################################################
# tc_registry.rb
#
# Test case for the Windows::Registry module.
#####################################################################
require 'windows/registry'
require 'test/unit'

class RegistryFoo
   include Windows::Registry
end

class TC_Windows_Registry < Test::Unit::TestCase
   def setup
      @foo  = RegistryFoo.new
   end

   def test_numeric_constants
      assert_equal(0x80000000, RegistryFoo::HKEY_CLASSES_ROOT)
   end

   def test_method_constants
      assert_not_nil(RegistryFoo::RegCloseKey)
   end

   def teardown
      @foo  = nil
   end
end
