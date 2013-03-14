require 'rdoc/test_case'

class TestRDocContextSection < RDoc::TestCase

  def setup
    super

    @S = RDoc::Context::Section
    @s = @S.new nil, 'section', comment('# comment')
  end

  def test_aref
    assert_equal 'section', @s.aref

    assert_equal '5Buntitled-5D', @S.new(nil, nil, nil).aref

    assert_equal 'one+two', @S.new(nil, 'one two', nil).aref
  end

  def test_comment_equals
    @s.comment = RDoc::Comment.new "# :section: section\n"

    assert_equal "# comment", @s.comment.text

    @s.comment = RDoc::Comment.new "# :section: section\n# other"

    assert_equal "# comment\n# ---\n# other", @s.comment.text

    s = @S.new nil, nil, nil

    s.comment = RDoc::Comment.new "# :section:\n# other"

    assert_equal "# other", s.comment.text
  end

  def test_extract_comment
    assert_equal '',    @s.extract_comment(comment('')).text
    assert_equal '',    @s.extract_comment(comment("# :section: b\n")).text
    assert_equal '# c', @s.extract_comment(comment("# :section: b\n# c")).text
    assert_equal '# c',
                 @s.extract_comment(comment("# a\n# :section: b\n# c")).text
  end

  def test_sequence
    _, err = capture_io do
      assert_match(/\ASEC\d{5}\Z/, @s.sequence)
    end

    assert_equal "#{@S}#sequence is deprecated, use #aref\n", err
  end

end

