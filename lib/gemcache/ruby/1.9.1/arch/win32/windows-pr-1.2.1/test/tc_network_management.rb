#####################################################################
# tc_network_management.rb
#
# Test case for the Windows::NetworkManagement module.
#####################################################################
require 'windows/network/management'
require 'test/unit'

class NetworkManagementFoo
   include Windows::Network::Management
end

class TC_Windows_Network_Management < Test::Unit::TestCase
   def setup
      @foo = NetworkManagementFoo.new
   end

   def test_numeric_constants
      assert_equal(0, NetworkManagementFoo::NERR_Success)
      assert_equal(0xFFFFFFFF, NetworkManagementFoo::MAX_PREFERRED_LENGTH)
      assert_equal(0x00000001, NetworkManagementFoo::SV_TYPE_WORKSTATION)
   end
   
   def test_method_constants
      assert_not_nil(NetworkManagementFoo::NetAlertRaise)
      assert_not_nil(NetworkManagementFoo::NetAlertRaiseEx)
   end
   
   def teardown
      @foo = nil
   end
end
