require 'minitest/autorun'
require 'rbreadline'

class TestRbReadline < Minitest::Test
  def test_versions
    assert_equal('5.2', RbReadline::RL_LIBRARY_VERSION)
    assert_equal(0x0502, RbReadline::RL_READLINE_VERSION)
  end

  def test_rl_adjust_point
    encoding_name = RbReadline.instance_variable_get(:@encoding_name)
    RbReadline.instance_variable_set(:@encoding_name, Encoding.find('UTF-8'))

    assert_equal(0, RbReadline._rl_adjust_point("a".force_encoding('ASCII-8BIT'), 0))
    assert_equal(0, RbReadline._rl_adjust_point("a".force_encoding('ASCII-8BIT'), 1))
    assert_equal(0, RbReadline._rl_adjust_point(("a" * 40).force_encoding('ASCII-8BIT'), 0))
    assert_equal(0, RbReadline._rl_adjust_point(("a" * 40).force_encoding('ASCII-8BIT'), 40))
    assert_equal(2, RbReadline._rl_adjust_point(("\u3042" * 10).force_encoding('ASCII-8BIT'), 1))
    assert_equal(1, RbReadline._rl_adjust_point(("\u3042" * 15).force_encoding('ASCII-8BIT'), 38))
  ensure
    RbReadline.instance_variable_set(:@encoding_name, encoding_name)
  end if defined?(Encoding)
end
