require 'rdoc/test_case'

class TestRDocTokenStream < RDoc::TestCase

  def test_class_to_html
    tokens = [
      RDoc::RubyToken::TkCONSTANT. new(0, 0, 0, 'CONSTANT'),
      RDoc::RubyToken::TkDEF.      new(0, 0, 0, 'KW'),
      RDoc::RubyToken::TkIVAR.     new(0, 0, 0, 'IVAR'),
      RDoc::RubyToken::TkOp.       new(0, 0, 0, 'Op'),
      RDoc::RubyToken::TkId.       new(0, 0, 0, 'Id'),
      RDoc::RubyToken::TkNode.     new(0, 0, 0, 'Node'),
      RDoc::RubyToken::TkCOMMENT.  new(0, 0, 0, 'COMMENT'),
      RDoc::RubyToken::TkREGEXP.   new(0, 0, 0, 'REGEXP'),
      RDoc::RubyToken::TkSTRING.   new(0, 0, 0, 'STRING'),
      RDoc::RubyToken::TkVal.      new(0, 0, 0, 'Val'),
      RDoc::RubyToken::TkBACKSLASH.new(0, 0, 0, '\\'),
    ]

    expected = [
      '<span class="ruby-constant">CONSTANT</span>',
      '<span class="ruby-keyword">KW</span>',
      '<span class="ruby-ivar">IVAR</span>',
      '<span class="ruby-operator">Op</span>',
      '<span class="ruby-identifier">Id</span>',
      '<span class="ruby-node">Node</span>',
      '<span class="ruby-comment">COMMENT</span>',
      '<span class="ruby-regexp">REGEXP</span>',
      '<span class="ruby-string">STRING</span>',
      '<span class="ruby-value">Val</span>',
      '\\'
    ].join

    assert_equal expected, RDoc::TokenStream.to_html(tokens)
  end

  def test_class_to_html_empty
    assert_equal '', RDoc::TokenStream.to_html([])
  end

end

