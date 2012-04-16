require 'rdoc/test_case'

class TestRDocParserRd < RDoc::TestCase

  def setup
    super

    @RP = RDoc::Parser

    @tempfile = Tempfile.new self.class.name
    filename = @tempfile.path

    @top_level = RDoc::TopLevel.new filename
    @fn = filename
    @options = RDoc::Options.new
    @stats = RDoc::Stats.new 0
  end

  def teardown
    super

    @tempfile.close
  end

  def test_file
    assert_kind_of RDoc::Parser::Text, util_parser('')
  end

  def test_class_can_parse
    assert_equal @RP::RD, @RP.can_parse('foo.rd')
    assert_equal @RP::RD, @RP.can_parse('foo.rd.ja')
  end

  def test_scan
    parser = util_parser 'it ((*really*)) works'

    expected =
      @RM::Document.new(
        @RM::Paragraph.new('it <em>really</em> works'))
    expected.file = @top_level

    parser.scan

    assert_equal expected, @top_level.comment.parse
  end

  def util_parser content
    RDoc::Parser::RD.new @top_level, @fn, content, @options, @stats
  end

end

