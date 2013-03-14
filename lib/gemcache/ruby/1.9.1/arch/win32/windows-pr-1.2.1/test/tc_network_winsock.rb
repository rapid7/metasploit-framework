#####################################################################
# tc_network_winsock.rb
#
# Test case for the Windows::Winsock module.
#####################################################################
require 'windows/network/winsock'
require 'test/unit'

class WinsockFoo
   include Windows::Network::Winsock
end

class TC_Windows_Network_Winsock < Test::Unit::TestCase
   def setup
      @foo = WinsockFoo.new
   end

   def test_numeric_constants
      assert_equal(0, WinsockFoo::NS_DEFAULT)
   end
   
   def test_method_constants
      assert_not_nil(WinsockFoo::GetTypeByName)
   end

   def test_method_mixins
      assert_respond_to(@foo, :gethostbyname)
      assert_respond_to(@foo, :GetTypeByName)
   end
   
   def teardown
      @foo = nil
   end
end
