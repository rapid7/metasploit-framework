require './test/test_helper'

class TestSocketInteraction < Test::Unit::TestCase
  def test_interaction # Issue #67
    require 'backports'
    require 'socket'
    assert_equal nil, UDPSocket.open{}
  end
end
