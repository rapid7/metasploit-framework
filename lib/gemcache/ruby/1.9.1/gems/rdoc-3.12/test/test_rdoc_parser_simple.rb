require 'rdoc/test_case'

class TestRDocParserSimple < RDoc::TestCase

  def setup
    super

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

  def test_initialize_metadata
    parser = util_parser ":unhandled: \n"

    assert_includes @top_level.metadata, 'unhandled'

    assert_equal ":unhandled: \n", parser.content
  end

  def test_remove_coding_comment
    parser = util_parser <<-TEXT
# -*- mode: rdoc; coding: utf-8; fill-column: 74; -*-

Regular expressions (<i>regexp</i>s) are patterns which describe the
contents of a string.
    TEXT

    parser.scan

    expected = <<-TEXT.strip
Regular expressions (<i>regexp</i>s) are patterns which describe the
contents of a string.
    TEXT

    assert_equal expected, @top_level.comment.text
  end

  # RDoc stops processing comments if it finds a comment line CONTAINING
  # '<tt>#--</tt>'. This can be used to separate external from internal
  # comments, or to stop a comment being associated with a method,
  # class, or module. Commenting CAN be turned back on with
  # a line that STARTS '<tt>#++</tt>'.
  #
  # I've seen guys that comment their code like this:
  #   # This method....
  #   #-----------------
  #   def method
  #
  # => either we do it only in ruby code, or we require the leading #
  #    (to avoid conflict with rules).
  #
  #   TODO: require the leading #, to provide the feature in simple text files.
  #   Note: in ruby & C code, we require '#--' & '#++' or '*--' & '*++',
  #   to allow rules:
  #
  #   # this is a comment
  #   #---
  #   # private text
  #   #+++
  #   # this is a rule:
  #   # ---

  def test_remove_private_comments
    parser = util_parser "foo\n\n--\nbar\n++\n\nbaz\n"

    parser.scan

    expected = "foo\n\n\nbaz"

    assert_equal expected, @top_level.comment.text
  end

  def test_remove_private_comments_rule
    parser = util_parser "foo\n---\nbar"

    parser.scan

    expected = "foo\n---\nbar"

    assert_equal expected, @top_level.comment.text
  end

  def test_remove_private_comments_star
    parser = util_parser "* foo\n* bar\n"

    parser.scan

    assert_equal "* foo\n* bar", @top_level.comment.text
  end

  def test_scan
    parser = util_parser 'it *really* works'

    parser.scan

    assert_equal 'it *really* works', @top_level.comment.text
  end

  def util_parser(content)
    RDoc::Parser::Simple.new @top_level, @fn, content, @options, @stats
  end

end

