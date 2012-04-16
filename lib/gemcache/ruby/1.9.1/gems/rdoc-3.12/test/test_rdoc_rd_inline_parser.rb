require 'rdoc/test_case'

class TestRDocRdInlineParser < RDoc::TestCase

  def setup
    super

    @block_parser = RDoc::RD::BlockParser.new
    @block_parser.instance_variable_set :@i, 0
    @inline_parser = RDoc::RD::InlineParser.new @block_parser
  end

  def test_parse
    assert_equal 'regular <em>emphasis</em>', parse('regular ((*emphasis*))')
  end

  def test_parse_code
    assert_equal '<code>text</code>', parse('(({text}))')
  end

  def test_parse_em
    assert_equal '<em>text</em>', parse('((*text*))')
  end

  def test_parse_footnote
    assert_equal '{*1}[rdoc-label:foottext-1:footmark-1]', parse('((-text-))')

    expected = [
      @RM::Paragraph.new('{^1}[rdoc-label:footmark-1:foottext-1]', 'text')
    ]

    assert_equal expected, @block_parser.footnotes
  end

  def test_parse_index
    assert_equal '<span id="label-text">text</span>', parse('((:text:))')

    assert_includes @block_parser.labels, 'text'
  end

  def test_parse_kbd
    assert_equal '<tt>text</tt>', parse('((%text%))')
  end

  def test_parse_multiple
    assert_equal '<em>one</em> <em>two</em>', parse('((*one*)) ((*two*))')
  end

  def test_parse_newline
    assert_equal "one\ntwo", parse("one\ntwo")
  end

  def test_parse_quote
    assert_equal 'one " two', parse('one " two')
  end

  def test_parse_ref
    assert_equal '{text}[rdoc-label:text]', parse('((<text>))')
  end

  def test_parse_ref_em
    assert_equal '{<em>text</em>}[rdoc-label:text]', parse('((<((*text*))>))')
  end

  def test_parse_ref_filename_quote
    assert_equal '{RD/foo}[rdoc-label:RD/foo]', parse('((<RD/"foo">))')
  end

  def test_parse_ref_filename
    assert_equal '{RD}[rdoc-label:RD/]', parse('((<RD/>))')
  end

  def test_parse_ref_quote
    assert_equal '{text \\"}[rdoc-label:text \\"]', parse('((<text \">))')
  end

  def test_parse_ref_quote_content
    assert_equal '{<em>text</em>}[rdoc-label:text]',
                 parse('((<"((*text*))">))')
  end

  def test_parse_ref_quote_content_multi
    assert_equal '{<em>one</em> <em>two</em>}[rdoc-label:one two]',
                 parse('((<"((*one*)) ((*two*))">))')
  end

  def test_parse_ref_substitute
    assert_equal '{text}[rdoc-label:thing]', parse('((<text|thing>))')
  end

  def test_parse_ref_substitute_element_quote
    assert_equal '{text}[rdoc-label:"RD"]',
                 parse('((<text|"RD">))')
  end

  def test_parse_ref_substitute_filename
    assert_equal '{text}[rdoc-label:RD/]', parse('((<text|RD/>))')
  end

  def test_parse_ref_substitute_filename_label
    assert_equal '{text}[rdoc-label:RD/label]',
                 parse('((<text|RD/label>))')
  end

  def test_parse_ref_substitute_filename_quote
    assert_equal '{text}[rdoc-label:"RD"/]', parse('((<text|"RD"/>))')
  end

  def test_parse_ref_substitute_multi_content
    assert_equal '{<em>one</em> two}[rdoc-label:thing]',
                 parse('((<((*one*)) two|thing>))')
  end

  def test_parse_ref_substitute_multi_content2
    assert_equal '{<em>one</em> \\" two}[rdoc-label:thing]',
                 parse('((<((*one*)) \" two|thing>))')
  end

  def test_parse_ref_substitute_multi_content3
    assert_equal '{<em>one</em> \\" <em>two</em>}[rdoc-label:thing]',
                 parse('((<((*one*)) \" ((*two*))|thing>))')
  end

  def test_parse_ref_substitute_quote
    assert_equal '{one | two}[rdoc-label:thing]',
                 parse('((<"one | two"|thing>))')
  end

  def test_parse_ref_substitute_quote_content
    assert_equal '{<em>text</em>}[rdoc-label:thing]',
                 parse('((<"((*text*))"|thing>))')
  end

  def test_parse_ref_substitute_url
    assert_equal '{text}[http://example]',
                 parse('((<text|URL:http://example>))')
  end

  def test_parse_ref_url
    assert_equal '{http://example}[http://example]',
                 parse('((<URL:http://example>))')
  end

  def test_parse_var
    assert_equal '+text+', parse('((|text|))')
  end

  def test_parse_verb
    assert_equal '<tt>text</tt>', parse("(('text'))")
  end

  def test_parse_verb_backslash
    assert_equal "<tt>(('text'))</tt>", parse("(('(('text\\'))'))")
  end

  def test_parse_verb_backslash_backslash
    assert_equal '<tt>text \\</tt>', parse("(('text \\\\'))")
  end

  def test_parse_verb_backslash_quote
    assert_equal '<tt>text "</tt>', parse("(('text \\\"'))")
  end

  def test_parse_verb_multiple
    assert_equal '<tt>((*text*))</tt>', parse("(('((*text*))'))")
  end

  def parse text
    @inline_parser.parse text
  end

end

