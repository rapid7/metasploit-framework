# coding: UTF-8
require 'test_helper'

class MarkdownTest < Redcarpet::TestCase
  def setup
    @renderer = Redcarpet::Render::HTML
  end

  def test_that_simple_one_liner_goes_to_html
    assert_equal "<p>Hello World.</p>", render("Hello World.")
  end

  def test_that_inline_markdown_goes_to_html
    assert_equal "<p><em>Hello World</em>!</p>", render('_Hello World_!')
  end

  def test_that_inline_markdown_starts_and_ends_correctly
    output   = render('_start _ foo_bar bar_baz _ end_ *italic* **bold** <a>_blah_</a>', with: [:no_intra_emphasis])
    expected = "<p><em>start _ foo_bar bar_baz _ end</em> <em>italic</em> <strong>bold</strong> <a><em>blah</em></a></p>"

    assert_equal expected, output

    output   = render("Run 'rake radiant:extensions:rbac_base:migrate'")
    expected = "<p>Run &#39;rake radiant:extensions:rbac_base:migrate&#39;</p>"

    assert_equal expected, output
  end

  def test_that_urls_are_not_doubly_escaped
    output = render('[Page 2](/search?query=Markdown+Test&page=2)')
    assert_equal "<p><a href=\"/search?query=Markdown+Test&page=2\">Page 2</a></p>", output
  end

  def test_simple_inline_html
    output   = render("before\n\n<div>\n  foo\n</div>\n\nafter")
    expected = "<p>before</p>\n\n<div>\n  foo\n</div>\n\n<p>after</p>"

    assert_equal expected, output
  end

  def test_that_html_blocks_do_not_require_their_own_end_tag_line
    output   = render("Para 1\n\n<div><pre>HTML block\n</pre></div>\n\nPara 2 [Link](#anchor)")
    expected = "<p>Para 1</p>\n\n<div><pre>HTML block\n</pre></div>\n\n<p>Para 2 <a href=\"#anchor\">Link</a></p>"

    assert_equal expected, output
  end

  # This isn't in the spec but is Markdown.pl behavior.
  def test_block_quotes_preceded_by_spaces
    output = render <<-Markdown.strip_heredoc
      A wise man once said:


       > Isn't it wonderful just to be alive.
    Markdown
    expected = <<-HTML.chomp.strip_heredoc
      <p>A wise man once said:</p>

      <blockquote>
      <p>Isn&#39;t it wonderful just to be alive.</p>
      </blockquote>
    HTML

    assert_equal expected, output
  end

  def test_para_before_block_html_should_not_wrap_in_p_tag
    output   = render("Things to watch out for\n<ul>\n<li>Blah</li>\n</ul>", with: [:lax_spacing])
    expected = "<p>Things to watch out for</p>\n\n<ul>\n<li>Blah</li>\n</ul>"

    assert_equal expected, output
  end

  # https://github.com/vmg/redcarpet/issues/111
  def test_p_with_less_than_4space_indent_should_not_be_part_of_last_list_item
    text = <<-Markdown
  * a
  * b
  * c

  This paragraph is not part of the list.
    Markdown
    expected = <<-HTML.chomp.strip_heredoc
      <ul>
      <li>a</li>
      <li>b</li>
      <li>c</li>
      </ul>

      <p>This paragraph is not part of the list.</p>
    HTML

    assert_equal expected, render(text)
  end

  # http://github.com/rtomayko/rdiscount/issues/#issue/13
  def test_headings_with_trailing_space
    text = "The Ant-Sugar Tales \n"       +
           "=================== \n\n"     +
           "By Candice Yellowflower   \n"

    assert_equal "<h1>The Ant-Sugar Tales </h1>\n\n<p>By Candice Yellowflower   </p>", render(text)
  end

  def test_that_intra_emphasis_works
    assert_equal "<p>foo<em>bar</em>baz</p>", render("foo_bar_baz")
    assert_equal "<p>foo_bar_baz</p>", render("foo_bar_baz", with: [:no_intra_emphasis])
  end

  def test_that_autolink_flag_works
    output   = render("http://github.com/rtomayko/rdiscount", with: [:autolink])
    expected = "<p><a href=\"http://github.com/rtomayko/rdiscount\">http://github.com/rtomayko/rdiscount</a></p>"

    assert_equal expected, output
  end

  def test_that_tags_can_have_dashes_and_underscores
    output   = render("foo <asdf-qwerty>bar</asdf-qwerty> and <a_b>baz</a_b>")
    expected = "<p>foo <asdf-qwerty>bar</asdf-qwerty> and <a_b>baz</a_b></p>"

    assert_equal expected, output
  end

  def test_link_syntax_is_not_processed_within_code_blocks
    output   = render("    This is a code block\n    This is a link [[1]] inside\n")
    expected = "<pre><code>This is a code block\nThis is a link [[1]] inside\n</code></pre>"

    assert_equal expected, output
  end

  def test_whitespace_after_urls
    output   = render("Japan: http://www.abc.net.au/news/events/japan-quake-2011/beforeafter.htm (yes, japan)", with: [:autolink])
    expected = %(<p>Japan: <a href="http://www.abc.net.au/news/events/japan-quake-2011/beforeafter.htm">http://www.abc.net.au/news/events/japan-quake-2011/beforeafter.htm</a> (yes, japan)</p>)

    assert_equal expected, output
  end

  def test_memory_leak_when_parsing_char_links
    render(<<-leaks.strip_heredoc)
      2. Identify the wild-type cluster and determine all clusters
         containing or contained by it:

             wildtype <- wildtype.cluster(h)
             wildtype.mask <- logical(nclust)
             wildtype.mask[c(contains(h, wildtype),
                             wildtype,
                             contained.by(h, wildtype))] <- TRUE

         This could be more elegant.
    leaks
  end

  def test_infinite_loop_in_header
    assert_equal "<h1>Body</h1>", render(<<-header.strip_heredoc)
      ######
      #Body#
      ######
    header
  end

  def test_a_hyphen_and_a_equal_should_not_be_converted_to_heading
    assert_equal "<p>-</p>", render("-")
    assert_equal "<p>=</p>", render("=")
  end

  def test_that_tables_flag_works
    text = <<-Markdown.strip_heredoc
       aaa | bbbb
      -----|------
      hello|sailor
    Markdown

    assert render(text) !~ /<table/
    assert render(text, with: [:tables]) =~ /<table/
  end

  def test_that_tables_work_with_org_table_syntax
    text = <<-Markdown.strip_heredoc
      | aaa | bbbb |
      |-----+------|
      |hello|sailor|
    Markdown

    assert render(text) !~ /<table/
    assert render(text, with: [:tables]) =~ /<table/
  end

  def test_strikethrough_flag_works
    text = "this is ~some~ striked ~~text~~"

    assert render(text) !~ /<del/
    assert render(text, with: [:strikethrough]) =~ /<del/
  end

  def test_underline_flag_works
    text   = "this is *some* text that is _underlined_. ___boom___"
    output = render(text, with: [:underline])

    refute render(text).include? '<u>underlined</u>'

    assert output.include? '<u>underlined</u>'
    assert output.include? '<em>some</em>'
  end

  def test_highlight_flag_works
    text   = "this is ==highlighted=="
    output = render(text, with: [:highlight])

    refute render(text).include? '<mark>highlighted</mark>'

    assert output.include? '<mark>highlighted</mark>'
  end

  def test_quote_flag_works
    text   = 'this is a "quote"'
    output = render(text, with: [:quote])

    refute render(text).include? '<q>quote</q>'

    assert_equal '<p>this is a <q>quote</q></p>', output
  end

  def test_that_fenced_flag_works
    text = <<-fenced.strip_heredoc
      This is a simple test

      ~~~~~
      This is some awesome code
          with tabs and shit
      ~~~
    fenced

    assert render(text) !~ /<code/
    assert render(text, with: [:fenced_code_blocks]) =~ /<code/
  end

  def test_that_fenced_flag_works_without_space
    text   = "foo\nbar\n```\nsome\ncode\n```\nbaz"
    output = render(text, with: [:fenced_code_blocks, :lax_spacing])

    assert output.include?("<pre><code>")

    output = render(text, with: [:fenced_code_blocks])
    assert !output.include?("<pre><code>")
  end

  def test_that_indented_code_preserves_references
    text = <<-indented.strip_heredoc
      This is normal text

          Link to [Google][1]

          [1]: http://google.com
    indented

    output = render(text, with: [:fenced_code_blocks])
    assert output.include?("[1]: http://google.com")
  end

  def test_that_fenced_flag_preserves_references
    text = <<-fenced.strip_heredoc
      This is normal text

      ```
      Link to [Google][1]

      [1]: http://google.com
      ```
    fenced

    out = render(text, with: [:fenced_code_blocks])
    assert out.include?("[1]: http://google.com")
  end

  def test_that_fenced_code_copies_language_verbatim_with_braces
    text = "```{rust,no_run}\nx = 'foo'\n```"
    html = render(text, with: [:fenced_code_blocks])

    assert_equal "<pre><code class=\"rust,no_run\">x = &#39;foo&#39;\n</code></pre>", html
  end

  def test_that_fenced_code_copies_language_verbatim
    text = "```rust,no_run\nx = 'foo'\n```"
    html = render(text, with: [:fenced_code_blocks])

    assert_equal "<pre><code class=\"rust,no_run\">x = &#39;foo&#39;\n</code></pre>", html
  end

  def test_that_indented_flag_works
    text = <<-indented.strip_heredoc
      This is a simple text

          This is some awesome code
          with shit

      And this is again a simple text
    indented

    assert render(text) =~ /<code/
    assert render(text, with: [:disable_indented_code_blocks]) !~ /<code/
  end

  def test_that_headers_are_linkable
    output   = render('### Hello [GitHub](http://github.com)')
    expected = "<h3>Hello <a href=\"http://github.com\">GitHub</a></h3>"

    assert_equal expected, output
  end

  def test_autolinking_with_ent_chars
    markdown = <<-Markdown.strip_heredoc
      This a stupid link: https://github.com/rtomayko/tilt/issues?milestone=1&state=open
    Markdown
    output   = render(markdown, with: [:autolink])

    assert_equal "<p>This a stupid link: <a href=\"https://github.com/rtomayko/tilt/issues?milestone=1&state=open\">https://github.com/rtomayko/tilt/issues?milestone=1&amp;state=open</a></p>", output
  end

  def test_spaced_headers
    output = render("#123 a header yes\n", with: [:space_after_headers])

    assert output !~ /<h1>/
  end

  def test_proper_intra_emphasis
    assert render("http://en.wikipedia.org/wiki/Dave_Allen_(comedian)", with: [:no_intra_emphasis]) !~ /<em>/
    assert render("this fails: hello_world_", with: [:no_intra_emphasis]) !~ /<em>/
    assert render("this also fails: hello_world_#bye", with: [:no_intra_emphasis]) !~ /<em>/
    assert render("this works: hello_my_world", with: [:no_intra_emphasis]) !~ /<em>/
    assert render("句中**粗體**測試", with: [:no_intra_emphasis]) =~ /<strong>/

    markdown = "This is (**bold**) and this_is_not_italic!"
    output   = "<p>This is (<strong>bold</strong>) and this_is_not_italic!</p>"

    assert_equal output, render(markdown, with: [:no_intra_emphasis])

    markdown = "This is \"**bold**\""
    output   = "<p>This is &quot;<strong>bold</strong>&quot;</p>"
    assert_equal output, render(markdown, with: [:no_intra_emphasis])
  end

  def test_emphasis_escaping
    assert_equal "<p><strong>foo*</strong> <em>dd_dd</em></p>", render("**foo\\*** _dd\\_dd_")
  end

  def test_char_escaping_when_highlighting
    output = render("==attribute\\===", with: [:highlight])

    assert_equal "<p><mark>attribute=</mark></p>", output
  end

  def test_ordered_lists_with_lax_spacing
    output = render("Foo:\n1. Foo\n2. Bar", with: [:lax_spacing])

    assert_match /<ol>/, output
    assert_match /<li>Foo<\/li>/, output
  end

  def test_references_with_tabs_after_colon
    output = render("[Link][id]\n[id]:\t\t\thttp://google.es")

    assert_equal "<p><a href=\"http://google.es\">Link</a></p>", output
  end

  def test_superscript
    output = render("this is the 2^nd time", with: [:superscript])

    assert_equal "<p>this is the 2<sup>nd</sup> time</p>", output
  end

  def test_superscript_enclosed_in_parenthesis
    output = render("this is the 2^(nd) time", with: [:superscript])

    assert_equal "<p>this is the 2<sup>nd</sup> time</p>", output
  end

  def test_no_rewind_into_previous_inline
    result = "<p><em>!dl</em><a href=\"mailto:1@danlec.com\">1@danlec.com</a></p>"
    output = render("_!dl_1@danlec.com", with: [:autolink])

    assert_equal result, output

    result = "<p>abc123<em><a href=\"http://www.foo.com\">www.foo.com</a></em>@foo.com</p>"
    output = render("abc123_www.foo.com_@foo.com", with: [:autolink])

    assert_equal result, output
  end

  def test_autolink_with_period_next_to_url
    result = %(<p>Checkout a cool site like <a href="https://github.com">https://github.com</a>.</p>)
    output = render("Checkout a cool site like https://github.com.", with: [:autolink])

    assert_equal result, output
  end

  def test_single_dashes_on_table_headers
    markdown = <<-Markdown.strip_heredoc
      | a | b |
      | - | - |
      | c | d |
    Markdown
    output   = render(markdown, with: [:tables])

    assert_match /<table>/, output
  end
end
