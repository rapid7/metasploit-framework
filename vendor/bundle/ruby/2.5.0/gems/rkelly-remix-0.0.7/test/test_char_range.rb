require File.dirname(__FILE__) + "/helper"

class CharRangeTest < NodeTestCase
  def test_advancing_empty_range
    a = RKelly::CharRange::EMPTY
    b = a.next("foo")

    assert_equal(1, b.from.line)
    assert_equal(1, b.from.char)
    assert_equal(0, b.from.index)

    assert_equal(1, b.to.line)
    assert_equal(3, b.to.char)
    assert_equal(2, b.to.index)
  end

  def test_advancing_with_multiline_string
    a = RKelly::CharRange.new(RKelly::CharPos.new(1,1,0), RKelly::CharPos.new(1,1,0))
    b = a.next("foo\nblah")

    assert_equal(1, b.from.line)
    assert_equal(2, b.from.char)
    assert_equal(1, b.from.index)

    assert_equal(2, b.to.line)
    assert_equal(4, b.to.char)
    assert_equal(8, b.to.index)
  end
end
