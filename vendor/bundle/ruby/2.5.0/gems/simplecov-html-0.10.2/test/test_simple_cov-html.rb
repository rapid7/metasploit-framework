require "helper"

class TestSimpleCovHtml < MiniTest::Unit::TestCase
  def test_defined
    assert defined?(SimpleCov::Formatter::HTMLFormatter)
    assert defined?(SimpleCov::Formatter::HTMLFormatter::VERSION)
  end
end
