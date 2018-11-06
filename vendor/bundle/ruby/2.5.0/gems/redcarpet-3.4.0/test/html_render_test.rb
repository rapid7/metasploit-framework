# coding: UTF-8
require 'test_helper'

class HTMLRenderTest < Redcarpet::TestCase
  def setup
    @renderer = Redcarpet::Render::HTML
  end

  # Hint: overrides filter_html, no_images and no_links
  def test_that_escape_html_works
    source = <<-HTML.strip_heredoc
      Through <em>NO</em> <script>DOUBLE NO</script>

      <script>BAD</script>

      <img src="/favicon.ico" />
    HTML
    expected = <<-HTML.chomp.strip_heredoc
      <p>Through &lt;em&gt;NO&lt;/em&gt; &lt;script&gt;DOUBLE NO&lt;/script&gt;</p>

      <p>&lt;script&gt;BAD&lt;/script&gt;</p>

      <p>&lt;img src=&quot;/favicon.ico&quot; /&gt;</p>
    HTML

    assert_equal expected, render(source, with: [:escape_html])
  end

  def test_that_filter_html_works
    markdown = 'Through <em>NO</em> <script>DOUBLE NO</script>'
    output   = render(markdown, with: [:filter_html])

    assert_equal "<p>Through NO DOUBLE NO</p>", output
  end

  def test_filter_html_doesnt_break_two_space_hard_break
    markdown = "Lorem,  \nipsum\n"
    output   = render(markdown, with: [:filter_html])

    assert_equal "<p>Lorem,<br>\nipsum</p>", output
  end

  def test_that_no_image_flag_works
    markdown = %(![dust mite](http://dust.mite/image.png) <img src="image.png" />)
    output   = render(markdown, with: [:no_images])

    assert_no_match %r{<img}, output
  end

  def test_that_links_with_ampersands_work
    markdown = %([/?a=b&c=d](/?a=b&c=d))
    output   = render(markdown)
    assert_equal "<p><a href=\"/?a=b&c=d\">/?a=b&amp;c=d</a></p>", output
  end

  def test_that_no_links_flag_works
    markdown = %([This link](http://example.net/) <a href="links.html">links</a>)
    output   = render(markdown, with: [:no_links])

    assert_no_match %r{<a }, output
  end

  def test_that_safelink_flag_works
    markdown = "[IRC](irc://chat.freenode.org/#freenode)"
    output   = render(markdown, with: [:safe_links_only])

    assert_equal "<p>[IRC](irc://chat.freenode.org/#freenode)</p>", output
  end

  def test_that_hard_wrap_works
    markdown = <<-Markdown.strip_heredoc
      Hello world,
      this is just a simple test

      With hard wraps
      and other *things*.
    Markdown
    output   = render(markdown, with: [:hard_wrap])

    assert_match %r{<br>}, output
  end

  def test_that_link_attributes_work
    rndr = Redcarpet::Render::HTML.new(:link_attributes => {:rel => 'blank'})
    md = Redcarpet::Markdown.new(rndr)
    assert md.render('This is a [simple](http://test.com) test.').include?('rel="blank"')
  end

  def test_that_link_works_with_quotes
    markdown = %([This'link"is](http://example.net/))
    expected = %(<p><a href="http://example.net/">This&#39;link&quot;is</a></p>)

    assert_equal expected, render(markdown)
    assert_equal expected, render(markdown, with: [:escape_html])
  end

  def test_that_code_emphasis_work
    markdown = <<-Markdown.strip_heredoc
      This should be **`a bold codespan`**
      However, this should be *`an emphasised codespan`*

      * **`ABC`** or **`DEF`**
      * Foo bar
    Markdown

    html = <<-HTML.chomp.strip_heredoc
      <p>This should be <strong><code>a bold codespan</code></strong>
      However, this should be <em><code>an emphasised codespan</code></em></p>

      <ul>
      <li><strong><code>ABC</code></strong> or <strong><code>DEF</code></strong></li>
      <li>Foo bar</li>
      </ul>
    HTML

    assert_equal html, render(markdown)
  end

  def test_that_parenthesis_are_handled_into_links
    markdown = %(The [bash man page](man:bash(1))!)
    expected = %(<p>The <a href="man:bash(1)">bash man page</a>!</p>)

    assert_equal expected, render(markdown)
  end

  def test_autolinking_works_as_expected
    markdown = "Uri ftp://user:pass@example.com/. Email foo@bar.com and link http://bar.com"
    output   = render(markdown, with: [:autolink])

    assert output.include? '<a href="ftp://user:pass@example.com/">ftp://user:pass@example.com/</a>'
    assert output.include? 'mailto:foo@bar.com'
    assert output.include? '<a href="http://bar.com">'
  end

  def test_that_footnotes_work
    markdown = <<-Markdown.strip_heredoc
      This is a footnote.[^1]

      [^1]: It provides additional information.
    Markdown

    html = <<-HTML.chomp.strip_heredoc
      <p>This is a footnote.<sup id="fnref1"><a href="#fn1" rel="footnote">1</a></sup></p>

      <div class="footnotes">
      <hr>
      <ol>

      <li id="fn1">
      <p>It provides additional information.&nbsp;<a href="#fnref1" rev="footnote">&#8617;</a></p>
      </li>

      </ol>
      </div>
    HTML

    output = render(markdown, with: [:footnotes])
    assert_equal html, output
  end

  def test_footnotes_enabled_but_missing_marker
    markdown = <<-Markdown.strip_heredoc
      Some text without a marker

      [^1] And a trailing definition
    Markdown
    html = <<-HTML.chomp.strip_heredoc
      <p>Some text without a marker</p>

      <p>[^1] And a trailing definition</p>
    HTML

    output = render(markdown, with: [:footnotes])
    assert_equal html, output
  end

  def test_footnotes_enabled_but_missing_definition
    markdown = "Some text with a marker[^1] but no definition."
    expected = "<p>Some text with a marker[^1] but no definition.</p>"

    output = render(markdown, with: [:footnotes])
    assert_equal expected, output
  end

  def test_autolink_short_domains
    markdown = "Example of uri ftp://auto/short/domains. Email auto@l.n and link http://a/u/t/o/s/h/o/r/t"
    output   = render(markdown, with: [:autolink])

    assert output.include? '<a href="ftp://auto/short/domains">ftp://auto/short/domains</a>'
    assert output.include? 'mailto:auto@l.n'
    assert output.include? '<a href="http://a/u/t/o/s/h/o/r/t">http://a/u/t/o/s/h/o/r/t</a>'
  end

  def test_that_prettify_works
    markdown = "\tclass Foo\nend"
    output   = render(markdown, with: [:prettify])

    assert output.include?("<pre><code class=\"prettyprint\">")

    markdown = "`class`"
    output   = render(markdown, with: [:prettify])

    assert output.include?("<code class=\"prettyprint\">")
  end

  def test_prettify_with_fenced_code_blocks
    markdown = "~~~ruby\ncode\n~~~"
    output   = render(markdown, with: [:fenced_code_blocks, :prettify])

    assert output.include?("<code class=\"prettyprint lang-ruby\">")
  end

  def test_safe_links_only_with_anchors
    markdown = "An [anchor link](#anchor) on a page."
    output   = render(markdown, with: [:safe_links_only])

    assert_match %r{<a href="#anchor">anchor link</a>}, output
  end

  def test_autolink_with_link_attributes
    options = { autolink: true, link_attributes: {rel: "nofollow"} }
    output  = render("https://github.com/", with: options)

    assert_match %r{rel="nofollow"}, output
  end

  def test_image_unsafe_src_with_safe_links_only
    markdown = "![foo](javascript:while(1);)"
    output   = render(markdown, with: [:safe_links_only])

    assert_not_match %r{img src}, output
  end

  def test_no_styles_option_inside_a_paragraph
    markdown = "Hello <style> foo { bar: baz; } </style> !"
    output   = render(markdown, with: [:no_styles])

    assert_no_match %r{<style>}, output
  end

  def test_no_styles_inside_html_block_rendering
    markdown = "<style> foo { bar: baz; } </style>"
    output   = render(markdown, with: [:no_styles])

    assert_no_match %r{<style>}, output
  end

  def test_non_ascii_removal_in_header_anchors
    markdown = "# Glühlampe"
    html = "<h1 id=\"gl-hlampe\">Glühlampe</h1>"

    assert_equal html, render(markdown, with: [:with_toc_data])
  end

  def test_utf8_only_header_anchors
    markdown = "# 見出し"
    html = "<h1 id=\"part-37870bfa194139f\">見出し</h1>"

    assert_equal html, render(markdown, with: [:with_toc_data])
  end

  def test_escape_entities_removal_from_anchor
    output = render("# Foo's & Bar's", with: [:with_toc_data])
    result = %(<h1 id="foos-bars">Foo&#39;s &amp; Bar&#39;s</h1>)

    assert_equal result, output
  end
end
