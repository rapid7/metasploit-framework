require 'rdoc/test_case'

class TestRDocMarkupToLabel < RDoc::TestCase

  def setup
    super

    @to = RDoc::Markup::ToLabel.new
  end

  def test_convert_bold
    assert_equal 'bold', @to.convert('<b>bold</b>')
    assert_equal 'bold', @to.convert('*bold*')
  end

  def test_convert_crossref
    assert_equal 'SomeClass', @to.convert('SomeClass')
    assert_equal 'SomeClass', @to.convert('\\SomeClass')

    assert_equal 'some_method', @to.convert('some_method')
    assert_equal 'some_method', @to.convert('\\some_method')

    assert_equal '%23some_method', @to.convert('#some_method')
    assert_equal '%23some_method', @to.convert('\\#some_method')
  end

  def test_convert_em
    assert_equal 'em', @to.convert('<em>em</em>')
    assert_equal 'em', @to.convert('*em*')
  end

  def test_convert_em_dash # for HTML conversion
    assert_equal '--', @to.convert('--')
  end

  def test_convert_escape
    assert_equal 'a+%3E+b', @to.convert('a > b')
  end

  def test_convert_tidylink
    assert_equal 'text', @to.convert('{text}[stuff]')
    assert_equal 'text', @to.convert('text[stuff]')
  end

  def test_convert_tt
    assert_equal 'tt', @to.convert('<tt>tt</tt>')
  end

end

