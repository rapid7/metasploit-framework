require 'rdoc/test_case'

class TestRDocGeneratorMarkup < RDoc::TestCase

  include RDoc::Text
  include RDoc::Generator::Markup

  def setup
    super

    @options = RDoc::Options.new
    @rdoc = RDoc::RDoc.new
    @rdoc.options = @options
    @parent = self
    @path = '/index.html'
    @symbols = {}

    RDoc::RDoc.current = @rdoc
  end

  def test_aref_to
    assert_equal 'Foo/Bar.html', aref_to('Foo/Bar.html')
  end

  def test_as_href
    assert_equal '../index.html', as_href('Foo/Bar.html')
  end

  def test_cvs_url
    assert_equal 'http://example/this_page',
                 cvs_url('http://example/', 'this_page')

    assert_equal 'http://example/?page=this_page&foo=bar',
                 cvs_url('http://example/?page=%s&foo=bar', 'this_page')
  end

  def test_description
    @comment = '= Hello'

    assert_equal "\n<h1 id=\"label-Hello\">Hello</h1>\n", description
  end

  def test_formatter
    assert_kind_of RDoc::Markup::ToHtmlCrossref, formatter
    refute formatter.show_hash
    assert_same self, formatter.context
  end

  attr_reader :path

  def find_symbol name
    @symbols[name]
  end

end

