require File.dirname(__FILE__) + "/helper"

class CharPosTest < NodeTestCase
  def test_advancing_empty_position
    a = RKelly::CharPos::EMPTY
    b = a.next("foo")

    assert_equal(1, b.line)
    assert_equal(3, b.char)
    assert_equal(2, b.index)
  end

  def test_advancing_with_single_line_string
    a = RKelly::CharPos.new(3,5,22)
    b = a.next("foo bar")

    assert_equal(3, b.line)
    assert_equal(12, b.char)
    assert_equal(29, b.index)
  end

  def test_advancing_with_multi_line_string
    a = RKelly::CharPos.new(3,5,22)
    b = a.next("\nfoo\nbar\nbaz")

    assert_equal(6, b.line)
    assert_equal(3, b.char)
    assert_equal(34, b.index)
  end

  def test_advancing_with_multi_line_string_ending_with_newline
    a = RKelly::CharPos.new(3,5,22)
    b = a.next("\nfoo\nbar\n")

    assert_equal(6, b.line)
    assert_equal(0, b.char)
    assert_equal(31, b.index)
  end
end
