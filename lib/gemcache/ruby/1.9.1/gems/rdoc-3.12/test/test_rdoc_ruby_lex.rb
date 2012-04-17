require 'rdoc/test_case'

class TestRDocRubyLex < RDoc::TestCase

  def setup
    @TK = RDoc::RubyToken
  end

  def mu_pp obj
    s = ''
    s = PP.pp obj, s
    s = s.force_encoding(Encoding.default_external) if defined? Encoding
    s.chomp
  end

  def test_class_tokenize
    tokens = RDoc::RubyLex.tokenize "def x() end", nil

    expected = [
      @TK::TkDEF       .new( 0, 1,  0, "def"),
      @TK::TkSPACE     .new( 3, 1,  3, " "),
      @TK::TkIDENTIFIER.new( 4, 1,  4, "x"),
      @TK::TkLPAREN    .new( 5, 1,  5, "("),
      @TK::TkRPAREN    .new( 6, 1,  6, ")"),
      @TK::TkSPACE     .new( 7, 1,  7, " "),
      @TK::TkEND       .new( 8, 1,  8, "end"),
      @TK::TkNL        .new(11, 1, 11, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_class_tokenize_def_heredoc
    tokens = RDoc::RubyLex.tokenize <<-'RUBY', nil
def x
  <<E
Line 1
Line 2
E
end
    RUBY

    expected = [
      @TK::TkDEF       .new( 0, 1,  0, 'def'),
      @TK::TkSPACE     .new( 3, 1,  3, ' '),
      @TK::TkIDENTIFIER.new( 4, 1,  4, 'x'),
      @TK::TkNL        .new( 5, 1,  5, "\n"),
      @TK::TkSPACE     .new( 6, 2,  0, '  '),
      @TK::TkSTRING    .new( 8, 2,  2, %Q{"Line 1\nLine 2\n"}),
      @TK::TkNL        .new(27, 5, 28, "\n"),
      @TK::TkEND       .new(28, 6,  0, 'end'),
      @TK::TkNL        .new(31, 6, 28, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_class_tokenize_heredoc_indent
    tokens = RDoc::RubyLex.tokenize <<-'RUBY', nil
string = <<-STRING
Line 1
Line 2
STRING
    RUBY

    expected = [
      @TK::TkIDENTIFIER.new( 0, 1,  0, 'string'),
      @TK::TkSPACE     .new( 6, 1,  6, ' '),
      @TK::TkASSIGN    .new( 7, 1,  7, '='),
      @TK::TkSPACE     .new( 8, 1,  8, ' '),
      @TK::TkSTRING    .new( 9, 1,  9, %Q{"Line 1\nLine 2\n"}),
      @TK::TkNL        .new(39, 4, 40, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_class_tokenize_heredoc_percent_N
    tokens = RDoc::RubyLex.tokenize <<-'RUBY', nil
a b <<-U
%N
U
    RUBY

    expected = [
      @TK::TkIDENTIFIER.new( 0, 1,  0, 'a'),
      @TK::TkSPACE     .new( 1, 1,  1, ' '),
      @TK::TkIDENTIFIER.new( 2, 1,  2, 'b'),
      @TK::TkSPACE     .new( 3, 1,  3, ' '),
      @TK::TkSTRING    .new( 4, 1,  4, %Q{"%N\n"}),
      @TK::TkNL        .new(13, 3, 14, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_class_tokenize_percent_w
    tokens = RDoc::RubyLex.tokenize '%w[hi]', nil

    expected = [
      @TK::TkDSTRING.new( 0, 1,  0, '%w[hi]'),
      @TK::TkNL     .new( 6, 1, 6, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_class_tokenize_string
    tokens = RDoc::RubyLex.tokenize "'hi'", nil

    expected = [
      @TK::TkSTRING.new( 0, 1,  0, "'hi'"),
      @TK::TkNL    .new( 4, 1,  4, "\n"),
    ]

    assert_equal expected, tokens
  end

  def test_unary_minus
    ruby_lex = RDoc::RubyLex.new("-1", nil)
    assert_equal("-1", ruby_lex.token.value)

    ruby_lex = RDoc::RubyLex.new("a[-2]", nil)
    2.times { ruby_lex.token } # skip "a" and "["
    assert_equal("-2", ruby_lex.token.value)

    ruby_lex = RDoc::RubyLex.new("a[0..-12]", nil)
    4.times { ruby_lex.token } # skip "a", "[", "0", and ".."
    assert_equal("-12", ruby_lex.token.value)

    ruby_lex = RDoc::RubyLex.new("0+-0.1", nil)
    2.times { ruby_lex.token } # skip "0" and "+"
    assert_equal("-0.1", ruby_lex.token.value)
  end

end

