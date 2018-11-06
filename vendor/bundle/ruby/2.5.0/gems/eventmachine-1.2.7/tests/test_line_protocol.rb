require 'em_test_helper'

class TestLineProtocol < Test::Unit::TestCase
  class LineProtocolTestClass
    include EM::Protocols::LineProtocol

    def lines
      @lines ||= []
    end

    def receive_line(line)
      lines << line
    end
  end

  def setup
    @proto = LineProtocolTestClass.new
  end

  def test_simple_split_line
    @proto.receive_data("this is")
    assert_equal([], @proto.lines)

    @proto.receive_data(" a test\n")
    assert_equal(["this is a test"], @proto.lines)
  end

  def test_simple_lines
    @proto.receive_data("aaa\nbbb\r\nccc\nddd")
    assert_equal(%w(aaa bbb ccc), @proto.lines)
  end

end
