require 'em_test_helper'

class TestConnectionWrite < Test::Unit::TestCase

  # This test takes advantage of the fact that EM::_RunSelectOnce iterates over the connections twice:
  #   - once to determine which ones to call Write() on
  #   - and once to call Write() on each of them.
  #
  # But state may change in the meantime before Write() is finally called.
  # And that is what we try to exploit to get Write() to be called when bWatchOnly is true, and bNotifyWritable is false,
  # to cause an assertion failure.

  module SimpleClient
    def notify_writable
      $conn2.notify_writable = false  # Being naughty in callback
      # If this doesn't crash anything, the test passed!
    end
  end

  def test_with_naughty_callback
    EM.run do
      r1, _ = IO.pipe
      r2, _ = IO.pipe

      # Adding EM.watches
      $conn1 = EM.watch(r1, SimpleClient)
      $conn2 = EM.watch(r2, SimpleClient)

      $conn1.notify_writable = true
      $conn2.notify_writable = true

      EM.stop
    end
  end
end
