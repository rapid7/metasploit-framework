require 'test_helper'

class HTML5Test < Redcarpet::TestCase
  def test_that_html5_works
    section = <<-HTML.chomp.strip_heredoc
      <section>
        <p>The quick brown fox jumps over the lazy dog.</p>
      </section>
    HTML

    figure = <<-HTML.chomp.strip_heredoc
      <figure>
        <img src="http://example.org/image.jpg" alt="">
        <figcaption>
          <p>Hello world!</p>
        </figcaption>
      </figure>
    HTML

    assert_renders section, section
    assert_renders figure, figure
  end

  def test_that_html5_works_with_code_blocks
    section = <<-HTML
\t<section>
\t\t<p>The quick brown fox jumps over the lazy dog.</p>
\t</section>
    HTML

    section_expected = <<-HTML.chomp.strip_heredoc
      <pre><code>&lt;section&gt;
          &lt;p&gt;The quick brown fox jumps over the lazy dog.&lt;/p&gt;
      &lt;/section&gt;
      </code></pre>
    HTML

    header = <<-HTML
    <header>
        <hgroup>
            <h1>Section heading</h1>
            <h2>Subhead</h2>
        </hgroup>
    </header>
    HTML

    header_expected = <<-HTML.chomp.strip_heredoc
      <pre><code>&lt;header&gt;
          &lt;hgroup&gt;
              &lt;h1&gt;Section heading&lt;/h1&gt;
              &lt;h2&gt;Subhead&lt;/h2&gt;
          &lt;/hgroup&gt;
      &lt;/header&gt;
      </code></pre>
    HTML

    assert_renders section_expected, section
    assert_renders header_expected, header
  end

  def test_script_tag_recognition
    html = <<-HTML.chomp.strip_heredoc
      <script type="text/javascript">
        alert('Foo!');
      </script>
    HTML

    assert_renders html, html
  end

  def test_new_html5_tags_not_escaped
    details = <<-HTML.chomp.strip_heredoc
      <details>
        log:

      </details>
    HTML

    assert_renders details, details
  end

end
