# coding: UTF-8
require 'test_helper'

class RedcarpetCompatTest < Redcarpet::TestCase
  def test_simple_compat_api
    html = RedcarpetCompat.new("This is_just_a test").to_html
    assert_equal "<p>This is<em>just</em>a test</p>\n", html
  end

  def test_compat_api_enables_extensions
    html = RedcarpetCompat.new("This is_just_a test", :no_intra_emphasis).to_html
    assert_equal "<p>This is_just_a test</p>\n", html
  end

  def test_compat_api_knows_fenced_code_extension
    text = "```ruby\nx = 'foo'\n```"
    html = RedcarpetCompat.new(text, :fenced_code).to_html
    assert_equal "<pre><code class=\"ruby\">x = &#39;foo&#39;\n</code></pre>\n", html
  end

  def test_compat_api_ignores_gh_blockcode_extension
    text = "```ruby\nx = 'foo'\n```"
    html = RedcarpetCompat.new(text, :fenced_code, :gh_blockcode).to_html
    assert_equal "<pre><code class=\"ruby\">x = &#39;foo&#39;\n</code></pre>\n", html
  end

  def test_compat_api_knows_no_intraemphasis_extension
    html = RedcarpetCompat.new("This is_just_a test", :no_intraemphasis).to_html
    assert_equal "<p>This is_just_a test</p>\n", html
  end

  def test_translate_outdated_extensions
    # these extensions are no longer used
    exts = [:gh_blockcode, :no_tables, :smart, :strict]
    html = RedcarpetCompat.new('"TEST"', *exts).to_html
    assert_equal "<p>&quot;TEST&quot;</p>\n", html
  end
end
