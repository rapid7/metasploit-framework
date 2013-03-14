# coding: UTF-8
require 'tilt'

begin
require 'nokogiri'

module MarkdownTests
  def self.included(mod)
    class << mod
      def template(t = nil)
        t.nil? ? @template : @template = t
      end
    end
  end

  def render(text, options = {})
    self.class.template.new(options) { text }.render
  end

  def normalize(html)
    Nokogiri::HTML.fragment(html).to_s
  end

  def nrender(text, options = {})
    html = render(text, options)
    html.encode!("UTF-8") if html.respond_to?(:encode)
    normalize(html)
  end
  
  def test_escape_html
    html = nrender "Hello <b>World</b>"
    assert_equal "<p>Hello <b>World</b></p>", html
  end

  def test_escape_html_false
    html = nrender "Hello <b>World</b>", :escape_html => false
    assert_equal "<p>Hello <b>World</b></p>", html
  end

  def test_escape_html_true
    if self.class.template == Tilt::RedcarpetTemplate
      flunk "redcarpet doesn't support :escape_html yet"
    end
    html = nrender "Hello <b>World</b>", :escape_html => true
    assert_equal "<p>Hello &lt;b&gt;World&lt;/b&gt;</p>", html
  end

  def test_smart_quotes
    html = nrender 'Hello "World"'
    assert_equal '<p>Hello "World"</p>', html
  end

  def test_smart_quotes_false
    html = nrender 'Hello "World"', :smartypants => false
    assert_equal '<p>Hello "World"</p>', html
  end

  def test_smart_quotes_true
    html = nrender 'Hello "World"', :smartypants => true
    assert_equal '<p>Hello “World”</p>', html
  end

  def test_smarty_pants
    html = nrender "Hello ``World'' -- This is --- a test ..."
    assert_equal "<p>Hello ``World'' -- This is --- a test ...</p>", html
  end

  def test_smarty_pants_false
    html = nrender "Hello ``World'' -- This is --- a test ...", :smartypants => false
    assert_equal "<p>Hello ``World'' -- This is --- a test ...</p>", html
  end

  def test_smarty_pants_true
    html = nrender "Hello ``World'' -- This is --- a test ...", :smartypants => true
    assert_equal "<p>Hello “World” — This is —– a test …</p>", html
  end
end

begin
  require 'rdiscount'

  class MarkdownRDiscountTest < Test::Unit::TestCase
    include MarkdownTests
    template Tilt::RDiscountTemplate
  end
rescue LoadError => boom
  # It should already be warned in the main tests
end

begin
  require 'redcarpet'

  class MarkdownRedcarpetTest < Test::Unit::TestCase
    include MarkdownTests
    template Tilt::RedcarpetTemplate
    # Doesn't support escaping
    undef test_escape_html_true

    def test_smarty_pants_true
      html = nrender "Hello ``World'' -- This is --- a test ...", :smartypants => true
      assert_equal "<p>Hello “World” – This is — a test …</p>", html
    end
  end
rescue LoadError => boom
  # It should already be warned in the main tests
end

begin
  require 'bluecloth'

  class MarkdownBlueClothTest < Test::Unit::TestCase
    include MarkdownTests
    template Tilt::BlueClothTemplate
  end
rescue LoadError => boom
  # It should already be warned in the main tests
end

begin
  require 'kramdown'

  class MarkdownKramdownTest < Test::Unit::TestCase
    include MarkdownTests
    template Tilt::KramdownTemplate
    # Doesn't support escaping
    undef test_escape_html_true
    # Smarty Pants is *always* on, but doesn't support it fully
    undef test_smarty_pants
    undef test_smarty_pants_false
    undef test_smarty_pants_true
  end
rescue LoadError => boom
  # It should already be warned in the main tests
end

  
begin
  require 'maruku'

  class MarkdownMarukuTest < Test::Unit::TestCase
    include MarkdownTests
    template Tilt::MarukuTemplate
    # Doesn't support escaping
    undef test_escape_html_true
    # Doesn't support Smarty Pants, and even fails on ``Foobar''
    undef test_smarty_pants
    undef test_smarty_pants_false
    undef test_smarty_pants_true
    # Smart Quotes is always on
    undef test_smart_quotes
    undef test_smart_quotes_false
  end
rescue LoadError => boom
  # It should already be warned in the main tests
end

rescue LoadError
  warn "Markdown tests need Nokogiri\n"
end


