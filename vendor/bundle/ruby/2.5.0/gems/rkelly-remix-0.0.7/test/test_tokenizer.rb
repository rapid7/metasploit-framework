# -*- coding: utf-8 -*-
require File.dirname(__FILE__) + "/helper"

class TokenizerTest < Test::Unit::TestCase
  def setup
    @tokenizer = RKelly::Tokenizer.new
  end

  {
    :space  => " ",
    :tab => "\t",
    :form_feed  => "\f",
    :vertical_tab  => "\v",
    :no_break_space  => [0x00A0].pack("U"),
    :ogham_space_mark => [0x1680].pack("U"),
    :en_quad => [0x2000].pack("U"),
    :em_quad => [0x2001].pack("U"),
    :en_space => [0x2002].pack("U"),
    :em_space => [0x2003].pack("U"),
    :three_per_em_space => [0x2004].pack("U"),
    :four_per_em_space => [0x2005].pack("U"),
    :six_per_em_space => [0x2006].pack("U"),
    :figure_space => [0x2007].pack("U"),
    :punctuation_space => [0x2008].pack("U"),
    :thin_space => [0x2009].pack("U"),
    :hair_space => [0x200a].pack("U"),
    :narrow_no_break_space => [0x202f].pack("U"),
    :medium_mathematical_space => [0x205f].pack("U"),
    :ideographic_space => [0x3000].pack("U"),

    # Line terminators
    :newline  => "\n",
    :carriage_return  => "\r",
    :line_separator => [0x2028].pack("U"),
    :paragraph_separator => [0x2029].pack("U"),
  }.each do |name, char|
    define_method(:"test_whitespace_#{name}") do
      assert_equal([[:S, char]], @tokenizer.tokenize(char))
    end
  end

  def assert_tokens(expected, actual)
    assert_equal(expected, actual.select { |x| x[0] != :S })
  end

  def test_comments
    tokens = @tokenizer.tokenize("/** Fooo */")
    assert_tokens([[:COMMENT, '/** Fooo */']], tokens)
  end

  def test_string_single_quote
    tokens = @tokenizer.tokenize("foo = 'hello world';")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:STRING, "'hello world'"],
                 [';', ';'],
    ], tokens)
  end

  def test_string_double_quote
    tokens = @tokenizer.tokenize('foo = "hello world";')
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:STRING, '"hello world"'],
                 [';', ';'],
    ], tokens)
  end

  def test_number_parse
    tokens = @tokenizer.tokenize('3.')
    assert_tokens([[:NUMBER, 3.0]], tokens)

    tokens = @tokenizer.tokenize('3.e1')
    assert_tokens([[:NUMBER, 30]], tokens)

    tokens = @tokenizer.tokenize('.001')
    assert_tokens([[:NUMBER, 0.001]], tokens)

    tokens = @tokenizer.tokenize('3.e-1')
    assert_tokens([[:NUMBER, 0.30]], tokens)
  end

  def test_identifier
    tokens = @tokenizer.tokenize("foo")
    assert_tokens([[:IDENT, 'foo']], tokens)
  end

  def test_ignore_identifier
    tokens = @tokenizer.tokenize("0foo")
    assert_tokens([[:NUMBER, 0], [:IDENT, 'foo']], tokens)
  end

  def test_increment
    tokens = @tokenizer.tokenize("foo += 1;")
    assert_tokens([
                 [:IDENT, 'foo'],
                 [:PLUSEQUAL, '+='],
                 [:NUMBER, 1],
                 [';', ';'],
    ], tokens)
  end

  def test_regular_expression
    tokens = @tokenizer.tokenize("foo = /=asdf/;")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:REGEXP, '/=asdf/'],
                 [';', ';'],
    ], tokens)
  end

  def test_regular_expression_invalid
    tokens = @tokenizer.tokenize("foo = (1 / 2) / 3")
    assert_tokens([[:IDENT, "foo"],
                   ["=", "="],
                   ["(", "("],
                   [:NUMBER, 1],
                   ["/", "/"],
                   [:NUMBER, 2],
                   [")", ")"],
                   ["/", "/"],
                   [:NUMBER, 3]
                  ], tokens)
  end

  def test_regular_expression_escape
    tokens = @tokenizer.tokenize('foo = /\/asdf/gi;')
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:REGEXP, '/\/asdf/gi'],
                 [';', ';'],
    ], tokens)
  end

  def test_regular_expression_with_slash_inside_charset
    tokens = @tokenizer.tokenize('foo = /[/]/;')
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:REGEXP, '/[/]/'],
                 [';', ';'],
    ], tokens)
  end

  def test_regular_expression_is_not_found_if_prev_token_implies_division
    {:IDENT => 'foo',
     :TRUE => 'true',
     :NUMBER => 1,
     ')' => ')',
     ']' => ']',
     '}' => '}'}.each do |name, value|
      tokens = @tokenizer.tokenize("#{value}/2/3")
      assert_tokens([
                  [name, value],
                   ["/", "/"],
                   [:NUMBER, 2],
                   ["/", "/"],
                   [:NUMBER, 3],
      ], tokens)
    end
  end

  def test_regular_expression_is_found_if_prev_token_is_non_literal_keyword
    {:RETURN => 'return',
     :THROW => 'throw'}.each do |name, value|
      tokens = @tokenizer.tokenize("#{value}/2/")
      assert_tokens([
                  [name, value],
                   [:REGEXP, "/2/"],
      ], tokens)
    end
  end

  def test_regular_expression_is_not_found_if_block_comment_with_re_modifier
    tokens = @tokenizer.tokenize("/**/i")
    assert_tokens([
      [:COMMENT, "/**/"],
      [:IDENT, "i"]
    ], tokens)
  end

  def test_comment_assign
    tokens = @tokenizer.tokenize("foo = /**/;")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:COMMENT, '/**/'],
                 [';', ';'],
    ], tokens)

    tokens = @tokenizer.tokenize("foo = //;")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:COMMENT, '//;'],
    ], tokens)
  end

  def test_unicode_string
    tokens = @tokenizer.tokenize("foo = 'öäüõ';")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:STRING, "'öäüõ'"],
                 [';', ';'],
    ], tokens)
  end

  def test_unicode_regex
    tokens = @tokenizer.tokenize("foo = /öäüõ/;")
    assert_tokens([
                 [:IDENT, 'foo'],
                 ['=', '='],
                 [:REGEXP, "/öäüõ/"],
                 [';', ';'],
    ], tokens)
  end

  %w{
    break case catch continue default delete do else finally for function
    if in instanceof new return switch this throw try typeof var void while
    with

    const true false null debugger
  }.each do |kw|
    define_method(:"test_keyword_#{kw}") do
      tokens = @tokenizer.tokenize(kw)
      assert_equal 1, tokens.length
      assert_equal([[kw.upcase.to_sym, kw]], tokens)
    end
  end

  %w{
    class enum extends super export import
  }.each do |rw|
    define_method(:"test_future_reserved_word_#{rw}_is_reserved") do
      tokens = @tokenizer.tokenize(rw)
      assert_equal 1, tokens.length
      assert_equal([[:RESERVED, rw]], tokens)
    end
  end

  %w{
    implements let private public yield
    interface package protected static
  }.each do |rw|
    define_method(:"test_future_reserved_word_#{rw}_is_identifier") do
      tokens = @tokenizer.tokenize(rw)
      assert_equal 1, tokens.length
      assert_equal([[:IDENT, rw]], tokens)
    end
  end

  {
    '=='  => :EQEQ,
    '!='  => :NE,
    '===' => :STREQ,
    '!==' => :STRNEQ,
    '<='   => :LE,
    '>='   => :GE,
    '||'  => :OR,
    '&&'  => :AND,
    '++'  => :PLUSPLUS,
    '--'  => :MINUSMINUS,
    '<<'  => :LSHIFT,
    '>>'  => :RSHIFT,
    '>>>' => :URSHIFT,
    '+='  => :PLUSEQUAL,
    '-='  => :MINUSEQUAL,
    '*='  => :MULTEQUAL,
    'null'  => :NULL,
    'true'  => :TRUE,
    'false' => :FALSE,
  }.each do |punctuator, sym|
    define_method(:"test_punctuator_#{sym}") do
      tokens = @tokenizer.tokenize(punctuator)
      assert_equal 1, tokens.length
      assert_equal([[sym, punctuator]], tokens)
    end
  end
end
