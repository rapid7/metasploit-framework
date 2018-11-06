# coding: UTF-8
require 'test_helper'

class SmartyHTMLTest < Redcarpet::TestCase
  def setup
    @renderer = Redcarpet::Render::SmartyHTML
  end

  def test_that_smartyhtml_converts_single_quotes
    markdown = render("They're not for sale.")
    assert_equal "<p>They&rsquo;re not for sale.</p>", markdown
  end

  def test_that_smartyhtml_converts_double_quotes
    rd = render(%("Quoted text"))
    assert_equal %(<p>&ldquo;Quoted text&rdquo;</p>), rd
  end

  def test_that_smartyhtml_converts_double_hyphen
    rd = render("double hyphen -- ndash")
    assert_equal "<p>double hyphen &ndash; ndash</p>", rd
  end

  def test_that_smartyhtml_converts_triple_hyphen
    rd = render("triple hyphen --- mdash")
    assert_equal "<p>triple hyphen &mdash; mdash</p>", rd
  end

  def test_that_smartyhtml_ignores_double_hyphen_in_code
    rd = render("double hyphen in `--option`")
    assert_equal "<p>double hyphen in <code>--option</code></p>", rd
  end

  def test_that_smartyhtml_ignores_pre
    rd = render("    It's a test of \"pre\"\n")
    expected = "It&#39;s a test of &quot;pre&quot;"
    assert rd.include?(expected), "\"#{rd}\" should contain \"#{expected}\""
  end

  def test_that_smartyhtml_ignores_code
    rd = render("`It's a test of \"code\"`\n")
    expected = "It&#39;s a test of &quot;code&quot;"
    assert rd.include?(expected), "\"#{rd}\" should contain \"#{expected}\""
  end
end
