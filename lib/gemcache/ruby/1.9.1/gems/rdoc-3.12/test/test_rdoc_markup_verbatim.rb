require 'rdoc/test_case'

class TestRDocMarkupVerbatim < RDoc::TestCase

  def test_ruby_eh
    verbatim = RDoc::Markup::Verbatim.new

    refute verbatim.ruby?

    verbatim.format = :ruby

    assert verbatim.ruby?
  end

end

