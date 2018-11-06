# coding: UTF-8
require 'test_helper'

class HTMLTOCRenderTest < Redcarpet::TestCase
  def setup
    @renderer = Redcarpet::Render::HTML_TOC
    @markdown = <<-Markdown.strip_heredoc
      # A title
      ## A __nice__ subtitle
      ## Another one
      ### A sub-sub-title
      ### 見出し
    Markdown
  end

  def test_simple_toc_render
    output = render(@markdown)

    assert output.start_with?("<ul>")
    assert output.end_with?("</ul>")

    assert_equal 3, output.scan("<ul>").length
    assert_equal 5, output.scan("<li>").length
  end

  def test_granular_toc_render
    output = render(@markdown, with: { nesting_level: 2 })

    assert output.start_with?("<ul>")
    assert output.end_with?("</ul>")

    assert_equal 3, output.scan("<li>").length
    assert !output.include?("A sub-sub title")
  end

  def test_toc_heading_id
    output = render(@markdown)

    assert_match /a-title/, output
    assert_match /a-nice-subtitle/, output
    assert_match /another-one/, output
    assert_match /a-sub-sub-title/, output
    assert_match /part-37870bfa194139f/, output
  end

  def test_toc_heading_with_hyphen_and_equal
    output = render("# Hello World\n\n-\n\n=")

    assert_equal 1, output.scan("<li>").length
    assert !output.include?('<a href=\"#\"></a>')
  end

  def test_anchor_generation_with_edge_cases
    # Imported from ActiveSupport::Inflector#parameterize's tests
    titles = {
      "Donald E. Knuth"                     => "donald-e-knuth",
      "Random text with *(bad)* characters" => "random-text-with-bad-characters",
      "!@#Surrounding bad characters!@#"    => "surrounding-bad-characters",
      "Squeeze   separators"                => "squeeze-separators",
      "Test with + sign"                    => "test-with-sign",
      "Test with a Namespaced::Class"       => "test-with-a-namespaced-class"
    }

    titles.each do |title, anchor|
      assert_match %("##{anchor}"), render("# #{title}")
    end
  end

  def test_inline_markup_is_not_escaped
    output = render(@markdown)

    assert_match "A <strong>nice</strong> subtitle", output
    assert_no_match %r{&lt;}, output
  end

  def test_inline_markup_escaping
    output = render(@markdown, with: [:escape_html])

    assert_match "&lt;strong&gt;", output
    assert_no_match %r{<strong>}, output
  end
end
