require 'rdoc/test_case'

class TestRDocRdBlockParser < RDoc::TestCase

  def setup
    super

    @block_parser = RDoc::RD::BlockParser.new
  end

  def mu_pp(obj)
    s = ""
    s = PP.pp obj, s
    s = s.force_encoding(Encoding.default_external) if defined? Encoding
    s.chomp
  end

  def test_parse_desclist
    list = <<-LIST
:one
  desc one
:two
  desc two
    LIST

    expected =
      doc(
        @RM::List.new(:NOTE,
          @RM::ListItem.new("one", @RM::Paragraph.new("desc one")),
          @RM::ListItem.new("two", @RM::Paragraph.new("desc two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_enumlist
    list = <<-LIST
(1) one
(1) two
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_enumlist_paragraphs
    list = <<-LIST
(1) one

    two
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("one"),
            @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_enumlist_multiline
    list = <<-LIST
(1) one
    two
    LIST

    contents = "one\n     two" # 1.8 vs 1.9

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new(*contents))))

    assert_equal expected, parse(list)
  end

  def test_parse_enumlist_verbatim
    list = <<-LIST
(1) item
      verbatim
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("item"),
            @RM::Verbatim.new("verbatim\n"))))

    assert_equal expected, parse(list)
  end

  def test_parse_enumlist_verbatim_continue
    list = <<-LIST
(1) one
      verbatim
    two
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("one"),
            @RM::Verbatim.new("verbatim\n"),
            @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_footnote
    expected =
      doc(
        @RM::Paragraph.new("{*1}[rdoc-label:foottext-1:footmark-1]"),
        @RM::Rule.new(1),
        @RM::Paragraph.new("{^1}[rdoc-label:footmark-1:foottext-1]", "text"))

    assert_equal expected, parse("((-text-))")
  end

  def test_parse_include
    @block_parser.include_path = [Dir.tmpdir]

    expected = doc(@RM::Include.new("parse_include", [Dir.tmpdir]))

    assert_equal expected, parse("<<< parse_include")
  end

  def test_parse_include_subtree
    @block_parser.include_path = [Dir.tmpdir]

    expected =
      doc(
        @RM::BlankLine.new,
        @RM::Paragraph.new("include <em>worked</em>"),
        @RM::BlankLine.new,
        @RM::BlankLine.new)

    Tempfile.open %w[parse_include .rd] do |io|
      io.puts "=begin\ninclude ((*worked*))\n=end"
      io.flush

      str = <<-STR
<<< #{File.basename io.path}
      STR

      assert_equal expected, parse(str)
    end
  end

  def test_parse_heading
    assert_equal doc(@RM::Heading.new(1, "H")), parse("= H")
    assert_equal doc(@RM::Heading.new(2, "H")), parse("== H")
    assert_equal doc(@RM::Heading.new(3, "H")), parse("=== H")
    assert_equal doc(@RM::Heading.new(4, "H")), parse("==== H")
    assert_equal doc(@RM::Heading.new(5, "H")), parse("+ H")
    assert_equal doc(@RM::Heading.new(6, "H")), parse("++ H")
  end

  def test_parse_itemlist
    list = <<-LIST
* one
* two
    LIST

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_itemlist_multiline
    list = <<-LIST
* one
  two
    LIST

    contents = "one\n   two" # 1.8 vs 1.9

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil, @RM::Paragraph.new(*contents))))

    assert_equal expected, parse(list)
  end

  def test_parse_itemlist_nest
    list = <<-LIST
* one
  * inner
* two
    LIST

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("one"),
            @RM::List.new(:BULLET,
              @RM::ListItem.new(nil, @RM::Paragraph.new("inner")))),
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_itemlist_paragraphs
    list = <<-LIST
* one

  two
    LIST

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("one"),
            @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_itemlist_verbatim
    list = <<-LIST
* item
    verbatim
    LIST

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("item"),
            @RM::Verbatim.new("verbatim\n"))))

    assert_equal expected, parse(list)
  end

  def test_parse_itemlist_verbatim_continue
    list = <<-LIST
* one
    verbatim
  two
    LIST

    expected =
      doc(
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("one"),
            @RM::Verbatim.new("verbatim\n"),
            @RM::Paragraph.new("two"))))

    assert_equal expected, parse(list)
  end

  def test_parse_lists
    list = <<-LIST
(1) one
(1) two
* three
* four
(1) five
(1) six
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("two"))),
        @RM::List.new(:BULLET,
          @RM::ListItem.new(nil, @RM::Paragraph.new("three")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("four"))),
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("five")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("six"))))

    assert_equal expected, parse(list)
  end

  def test_parse_lists_nest
    list = <<-LIST
(1) one
(1) two
      * three
      * four
(1) five
(1) six
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("two"),
            @RM::List.new(:BULLET,
              @RM::ListItem.new(nil, @RM::Paragraph.new("three")),
              @RM::ListItem.new(nil, @RM::Paragraph.new("four")))),
          @RM::ListItem.new(nil, @RM::Paragraph.new("five")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("six"))))

    assert_equal expected, parse(list)
  end

  def test_parse_lists_nest_verbatim
    list = <<-LIST
(1) one
(1) two
      * three
      * four
     verbatim
(1) five
(1) six
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("two"),
            @RM::List.new(:BULLET,
              @RM::ListItem.new(nil, @RM::Paragraph.new("three")),
              @RM::ListItem.new(nil, @RM::Paragraph.new("four"))),
            @RM::Verbatim.new("verbatim\n")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("five")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("six"))))

    assert_equal expected, parse(list)
  end

  def test_parse_lists_nest_verbatim2
    list = <<-LIST
(1) one
(1) two
      * three
      * four
      verbatim
(1) five
(1) six
    LIST

    expected =
      doc(
        @RM::List.new(:NUMBER,
          @RM::ListItem.new(nil, @RM::Paragraph.new("one")),
          @RM::ListItem.new(nil,
            @RM::Paragraph.new("two"),
            @RM::List.new(:BULLET,
              @RM::ListItem.new(nil, @RM::Paragraph.new("three")),
              @RM::ListItem.new(nil, @RM::Paragraph.new("four"))),
            @RM::Verbatim.new("verbatim\n")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("five")),
          @RM::ListItem.new(nil, @RM::Paragraph.new("six"))))

    assert_equal expected, parse(list)
  end

  def test_parse_methodlist
    list = <<-LIST
--- Array#each {|i| ... }
      yield block for each item.
--- Array#index(val)
      return index of first item which equals with val. if it hasn't
      same item, return nil.
    LIST

    expected =
      doc(
        @RM::List.new(:LABEL,
          @RM::ListItem.new(
            "<tt>Array#each {|i| ... }</tt>",
            @RM::Paragraph.new("yield block for each item.")),
          @RM::ListItem.new(
            "<tt>Array#index(val)</tt>",
            @RM::Paragraph.new("return index of first item which equals with val. if it hasn't same item, return nil."))))

    assert_equal expected, parse(list)
  end

  def test_parse_methodlist_empty
    list = <<-LIST
--- A#b

    LIST

    expected =
      doc(
        @RM::List.new(:LABEL,
          @RM::ListItem.new("<tt>A#b</tt>")))

    assert_equal expected, parse(list)
  end

  def test_parse_methodlist_paragraph
    list = <<-LIST
--- A#b

    one
    LIST

    expected =
      doc(
        @RM::List.new(:LABEL,
          @RM::ListItem.new(
            "<tt>A#b</tt>",
            @RM::Paragraph.new("one"))))

    assert_equal expected, parse(list)
  end

  def test_parse_methodlist_paragraph2
    list = <<-LIST.chomp
--- A#b

    one
two
    LIST

    expected =
      doc(
        @RM::List.new(:LABEL,
          @RM::ListItem.new(
            "<tt>A#b</tt>",
            @RM::Paragraph.new("one"))),
        @RM::Paragraph.new("two"))

    assert_equal expected, parse(list)
  end

  def test_parse_methodlist_paragraph_verbatim
    list = <<-LIST.chomp
--- A#b

    text
      verbatim
    LIST

    expected =
      doc(
        @RM::List.new(:LABEL,
          @RM::ListItem.new(
            "<tt>A#b</tt>",
            @RM::Paragraph.new("text"),
            @RM::Verbatim.new("verbatim\n"))))

    assert_equal expected, parse(list)
  end

  def test_parse_verbatim
    assert_equal doc(@RM::Verbatim.new("verbatim\n")), parse("  verbatim")
  end

  def test_parse_verbatim_blankline
    expected = doc(@RM::Verbatim.new("one\n", "\n", "two\n"))

    verbatim = <<-VERBATIM
  one

  two
    VERBATIM

    assert_equal expected, parse(verbatim)
  end

  def test_parse_verbatim_indent
    expected = doc(@RM::Verbatim.new("one\n", " two\n"))

    verbatim = <<-VERBATIM
  one
   two
    VERBATIM

    assert_equal expected, parse(verbatim)
  end

  def test_parse_verbatim_multi
    expected = doc(@RM::Verbatim.new("one\n", "two\n"))

    verbatim = <<-VERBATIM
  one
  two
    VERBATIM

    assert_equal expected, parse(verbatim)
  end

  def test_parse_textblock
    assert_equal doc(@RM::Paragraph.new("text")), parse("text")
  end

  def test_parse_textblock_multi
    expected = doc(@RM::Paragraph.new("one two"))

    assert_equal expected, parse("one\ntwo")
  end

  def doc *parts
    @RM::Document.new(*parts)
  end

  def parse text
    text = ["=begin", text, "=end"].join "\n"

    doc = @block_parser.parse text.lines.to_a

    assert_equal @RM::BlankLine.new, doc.parts.shift, "=begin blankline"
    assert_equal @RM::BlankLine.new, doc.parts.pop, "=end blankline"

    doc
  end

end

