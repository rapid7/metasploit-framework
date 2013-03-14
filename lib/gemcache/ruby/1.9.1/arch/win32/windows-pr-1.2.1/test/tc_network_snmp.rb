#####################################################################
# tc_network_snmp.rb
#
# Test case for the Windows::NetworkSNMP module.
#####################################################################
require 'windows/network/snmp'
require 'test/unit'

class NetworkSNMPFoo
   include Windows::Network::SNMP
end

class TC_Windows_Network_SNMP < Test::Unit::TestCase
   def setup
      @foo = NetworkSNMPFoo.new
   end

   def test_numeric_constants
      assert_equal(0, NetworkSNMPFoo::SNMPAPI_FAILURE)
      assert_equal(1, NetworkSNMPFoo::SNMPAPI_SUCCESS)
   end
   
   def test_method_constants
      assert_not_nil(NetworkSNMPFoo::SnmpCleanup)
      assert_not_nil(NetworkSNMPFoo::SnmpClose)
   end
   
   def teardown
      @foo = nil
   end
end
