require File.expand_path '../xref_test_case', __FILE__

class TestRDocMarkupToHtmlCrossref < XrefTestCase

  def setup
    super

    @to = RDoc::Markup::ToHtmlCrossref.new 'index.html', @c1, true
  end

  def test_convert_CROSSREF
    result = @to.convert 'C1'

    assert_equal para("<a href=\"C1.html\">C1</a>"), result
  end

  def test_convert_CROSSREF_label
    result = @to.convert 'C1@foo'
    assert_equal para("<a href=\"C1.html#label-foo\">foo at C1</a>"), result

    result = @to.convert 'C1#m@foo'
    assert_equal para("<a href=\"C1.html#method-i-m-label-foo\">foo at C1#m</a>"),
                 result
  end

  def test_convert_CROSSREF_label_period
    result = @to.convert 'C1@foo.'
    assert_equal para("<a href=\"C1.html#label-foo\">foo at C1</a>."), result
  end

  def test_convert_CROSSREF_label_space
    result = @to.convert 'C1@foo+bar'
    assert_equal para("<a href=\"C1.html#label-foo+bar\">foo bar at C1</a>"),
                 result
  end

  def test_convert_RDOCLINK_rdoc_ref
    result = @to.convert 'rdoc-ref:C1'

    assert_equal para("<a href=\"C1.html\">C1</a>"), result
  end

  def test_convert_RDOCLINK_rdoc_ref_method
    result = @to.convert 'rdoc-ref:C1#m'

    assert_equal para("<a href=\"C1.html#method-i-m\">#m</a>"), result
  end

  def test_convert_RDOCLINK_rdoc_ref_method_label
    result = @to.convert 'rdoc-ref:C1#m@foo'

    assert_equal para("<a href=\"C1.html#method-i-m-label-foo\">foo at C1#m</a>"),
                 result, 'rdoc-ref:C1#m@foo'
  end

  def test_convert_RDOCLINK_rdoc_ref_method_percent
    m = @c1.add_method RDoc::AnyMethod.new nil, '%'
    m.singleton = false

    result = @to.convert 'rdoc-ref:C1#%'

    assert_equal para("<a href=\"C1.html#method-i-25\">#%</a>"), result

    m.singleton = true

    result = @to.convert 'rdoc-ref:C1::%'

    assert_equal para("<a href=\"C1.html#method-c-25\">::%</a>"), result
  end

  def test_convert_RDOCLINK_rdoc_ref_method_percent_label
    m = @c1.add_method RDoc::AnyMethod.new nil, '%'
    m.singleton = false

    result = @to.convert 'rdoc-ref:C1#%@f'

    assert_equal para("<a href=\"C1.html#method-i-25-label-f\">f at C1#%</a>"),
                 result

    m.singleton = true

    result = @to.convert 'rdoc-ref:C1::%@f'

    assert_equal para("<a href=\"C1.html#method-c-25-label-f\">f at C1::%</a>"),
                 result
  end

  def test_convert_RDOCLINK_rdoc_ref_label
    result = @to.convert 'rdoc-ref:C1@foo'

    assert_equal para("<a href=\"C1.html#label-foo\">foo at C1</a>"), result,
                 'rdoc-ref:C1@foo'
  end

  def test_gen_url
    assert_equal '<a href="C1.html">Some class</a>',
                 @to.gen_url('rdoc-ref:C1', 'Some class')

    assert_equal '<a href="http://example">HTTP example</a>',
                 @to.gen_url('http://example', 'HTTP example')
  end

  def test_handle_special_CROSSREF
    assert_equal "<a href=\"C2/C3.html\">C2::C3</a>", SPECIAL('C2::C3')
  end

  def test_handle_special_CROSSREF_label
    assert_equal "<a href=\"C1.html#method-i-m-label-foo\">foo at C1#m</a>",
                  SPECIAL('C1#m@foo')
  end

  def test_handle_special_CROSSREF_show_hash_false
    @to.show_hash = false

    assert_equal "<a href=\"C1.html#method-i-m\">m</a>",
                 SPECIAL('#m')
  end

  def test_handle_special_HYPERLINK_rdoc
    readme = RDoc::TopLevel.new 'README.txt'
    readme.parser = RDoc::Parser::Simple

    @to = RDoc::Markup::ToHtmlCrossref.new 'C2.html', @c2, true

    link = @to.handle_special_HYPERLINK hyper 'C2::C3'

    assert_equal '<a href="C2/C3.html">C2::C3</a>', link

    link = @to.handle_special_HYPERLINK hyper 'C4'

    assert_equal '<a href="C4.html">C4</a>', link

    link = @to.handle_special_HYPERLINK hyper 'README.txt'

    assert_equal '<a href="README_txt.html">README.txt</a>', link
  end

  def test_handle_special_TIDYLINK_rdoc
    readme = RDoc::TopLevel.new 'README.txt'
    readme.parser = RDoc::Parser::Simple

    @to = RDoc::Markup::ToHtmlCrossref.new 'C2.html', @c2, true

    link = @to.handle_special_TIDYLINK tidy 'C2::C3'

    assert_equal '<a href="C2/C3.html">tidy</a>', link

    link = @to.handle_special_TIDYLINK tidy 'C4'

    assert_equal '<a href="C4.html">tidy</a>', link

    link = @to.handle_special_TIDYLINK tidy 'C1#m'

    assert_equal '<a href="C1.html#method-i-m">tidy</a>', link

    link = @to.handle_special_TIDYLINK tidy 'README.txt'

    assert_equal '<a href="README_txt.html">tidy</a>', link
  end

  def test_handle_special_TIDYLINK_label
    link = @to.handle_special_TIDYLINK tidy 'C1#m@foo'

    assert_equal "<a href=\"C1.html#method-i-m-label-foo\">tidy</a>",
                 link, 'C1#m@foo'
  end

  def test_link
    assert_equal 'n', @to.link('n', 'n')

    assert_equal '<a href="C1.html#method-c-m">::m</a>', @to.link('m', 'm')
  end

  def test_link_class_method_full
    assert_equal '<a href="Parent.html#method-c-m">Parent.m</a>',
                 @to.link('Parent::m', 'Parent::m')
  end

  def para text
    "\n<p>#{text}</p>\n"
  end

  def SPECIAL text
    @to.handle_special_CROSSREF special text
  end

  def hyper reference
    RDoc::Markup::Special.new 0, "rdoc-ref:#{reference}"
  end

  def special text
    RDoc::Markup::Special.new 0, text
  end

  def tidy reference
    RDoc::Markup::Special.new 0, "{tidy}[rdoc-ref:#{reference}]"
  end

end

