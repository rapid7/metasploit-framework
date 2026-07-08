# frozen_string_literal: true

require 'test/unit'
require 'msf/core'

class TestFtpMixinFrozenString < Test::Unit::TestCase
  include Msf

  def setup
    @module = Msf::Module.new
    @module.extend(Exploit::Remote::Ftp)
  end

  def test_ftpbuff_is_mutable
    # Initialize the FTP mixin
    @module.send(:initialize, {})

    # Access the internal @ftpbuff variable
    ftpbuff = @module.instance_variable_get(:@ftpbuff)

    # Verify it's not frozen
    assert_not_predicate(ftpbuff, :frozen?, "@ftpbuff should be mutable even with frozen_string_literal: true")

    # Verify we can modify it
    assert_nothing_raised do
      ftpbuff << "test data"
    end
  end

  def test_recv_ftp_resp_with_frozen_string_literal
    # This test verifies that recv_ftp_resp works correctly
    # when the module uses frozen_string_literal: true

    # Mock the socket
    mock_socket = Object.new
    def mock_socket.get
      "220 Welcome\r\n"
    end

    @module.instance_variable_set(:@sock, mock_socket)

    # This should not raise FrozenError
    assert_nothing_raised do
      result = @module.send(:recv_ftp_resp)
      assert_equal("220 Welcome", result)
    end
  end
end
