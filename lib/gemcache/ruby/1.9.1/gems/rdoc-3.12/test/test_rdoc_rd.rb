require 'rdoc/test_case'

class TestRDocRd < RDoc::TestCase

  def test_class_parse
    expected =
      @RM::Document.new(
        @RM::Paragraph.new('hello'))

    assert_equal expected, RDoc::RD.parse("hello")
  end

  def test_class_parse_begin_end
    expected =
      @RM::Document.new(
        @RM::Paragraph.new('hello'))

    assert_equal expected, RDoc::RD.parse("=begin\nhello\n=end\n")
  end

  def test_class_parse_newline
    expected =
      @RM::Document.new(
        @RM::Paragraph.new('hello'))

    assert_equal expected, RDoc::RD.parse("hello\n")
  end

end

