require 'em_test_helper'

class TestShutdownHooks < Test::Unit::TestCase
  def test_shutdown_hooks
    r = false
    EM.run {
      EM.add_shutdown_hook { r = true }
      EM.stop
    }
    assert_equal( true, r )
  end

  def test_hook_order
    r = []
    EM.run {
      EM.add_shutdown_hook { r << 2 }
      EM.add_shutdown_hook { r << 1 }
      EM.stop
    }
    assert_equal( [1, 2], r )
  end
end

