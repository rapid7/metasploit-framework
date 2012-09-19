#####################################################################
# tc_socket.rb
#
# Test case for the Windows::Socket module.
#####################################################################
require 'windows/socket'
require 'test/unit'

class TC_Windows_Socket < Test::Unit::TestCase
  include Windows::Socket

  def test_methods
    assert_respond_to(self, :accept)
    assert_respond_to(self, :AcceptEx)
  end

  def test_constants
    assert_equal(0, IPPROTO_IP)
  end
end
