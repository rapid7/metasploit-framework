require 'rdoc/test_case'

class TestRDocMarkupToHtml < RDoc::Markup::FormatterTestCase

  add_visitor_tests

  def setup
    super

    @to = RDoc::Markup::ToHtml.new
  end

  def test_class_gen_relative_url
    def gen(from, to)
      RDoc::Markup::ToHtml.gen_relative_url from, to
    end

    assert_equal 'a.html',    gen('a.html',   'a.html')
    assert_equal 'b.html',    gen('a.html',   'b.html')

    assert_equal 'd.html',    gen('a/c.html', 'a/d.html')
    assert_equal '../a.html', gen('a/c.html', 'a.html')
    assert_equal 'a/c.html',  gen('a.html',   'a/c.html')
  end

  def accept_blank_line
    assert_empty @to.res.join
  end

  def accept_document
    assert_equal "\n<p>hello</p>\n", @to.res.join
  end

  def accept_heading
    assert_equal "\n<h5 id=\"label-Hello\">Hello</h5>\n", @to.res.join
  end

  def accept_heading_1
    assert_equal "\n<h1 id=\"label-Hello\">Hello</h1>\n", @to.res.join
  end

  def accept_heading_2
    assert_equal "\n<h2 id=\"label-Hello\">Hello</h2>\n", @to.res.join
  end

  def accept_heading_3
    assert_equal "\n<h3 id=\"label-Hello\">Hello</h3>\n", @to.res.join
  end

  def accept_heading_4
    assert_equal "\n<h4 id=\"label-Hello\">Hello</h4>\n", @to.res.join
  end

  def accept_heading_b
    assert_equal "\n<h1 id=\"label-Hello\"><strong>Hello</strong></h1>\n",
                 @to.res.join
  end

  def accept_heading_suppressed_crossref
    assert_equal "\n<h1 id=\"label-Hello\">Hello</h1>\n", @to.res.join
  end

  def accept_list_end_bullet
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<ul></ul>\n", @to.res.join
  end

  def accept_list_end_label
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<dl class=\"rdoc-list label-list\"></dl>\n", @to.res.join
  end

  def accept_list_end_lalpha
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<ol style=\"list-style-type: lower-alpha\"></ol>\n", @to.res.join
  end

  def accept_list_end_number
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<ol></ol>\n", @to.res.join
  end

  def accept_list_end_note
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<dl class=\"rdoc-list note-list\"></dl>\n", @to.res.join
  end

  def accept_list_end_ualpha
    assert_equal [], @to.list
    assert_equal [], @to.in_list_entry

    assert_equal "<ol style=\"list-style-type: upper-alpha\"></ol>\n", @to.res.join
  end

  def accept_list_item_end_bullet
    assert_equal %w[</li>], @to.in_list_entry
  end

  def accept_list_item_end_label
    assert_equal %w[</dd>], @to.in_list_entry
  end

  def accept_list_item_end_lalpha
    assert_equal %w[</li>], @to.in_list_entry
  end

  def accept_list_item_end_note
    assert_equal %w[</dd>], @to.in_list_entry
  end

  def accept_list_item_end_number
    assert_equal %w[</li>], @to.in_list_entry
  end

  def accept_list_item_end_ualpha
    assert_equal %w[</li>], @to.in_list_entry
  end

  def accept_list_item_start_bullet
    assert_equal "<ul><li>", @to.res.join
  end

  def accept_list_item_start_label
    assert_equal "<dl class=\"rdoc-list label-list\"><dt>cat\n<dd>", @to.res.join
  end

  def accept_list_item_start_lalpha
    assert_equal "<ol style=\"list-style-type: lower-alpha\"><li>", @to.res.join
  end

  def accept_list_item_start_note
    assert_equal "<dl class=\"rdoc-list note-list\"><dt>cat\n<dd>",
                 @to.res.join
  end

  def accept_list_item_start_note_2
    expected = <<-EXPECTED
<dl class="rdoc-list note-list"><dt><code>teletype</code>
<dd>
<p>teletype description</p>
</dd></dl>
    EXPECTED

    assert_equal expected, @to.res.join
  end

  def accept_list_item_start_number
    assert_equal "<ol><li>", @to.res.join
  end

  def accept_list_item_start_ualpha
    assert_equal "<ol style=\"list-style-type: upper-alpha\"><li>", @to.res.join
  end

  def accept_list_start_bullet
    assert_equal [:BULLET], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal "<ul>", @to.res.join
  end

  def accept_list_start_label
    assert_equal [:LABEL], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal '<dl class="rdoc-list label-list">', @to.res.join
  end

  def accept_list_start_lalpha
    assert_equal [:LALPHA], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal "<ol style=\"list-style-type: lower-alpha\">", @to.res.join
  end

  def accept_list_start_note
    assert_equal [:NOTE], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal "<dl class=\"rdoc-list note-list\">", @to.res.join
  end

  def accept_list_start_number
    assert_equal [:NUMBER], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal "<ol>", @to.res.join
  end

  def accept_list_start_ualpha
    assert_equal [:UALPHA], @to.list
    assert_equal [false], @to.in_list_entry

    assert_equal "<ol style=\"list-style-type: upper-alpha\">", @to.res.join
  end

  def accept_paragraph
    assert_equal "\n<p>hi</p>\n", @to.res.join
  end

  def accept_paragraph_b
    assert_equal "\n<p>reg <strong>bold words</strong> reg</p>\n", @to.res.join
  end

  def accept_paragraph_i
    assert_equal "\n<p>reg <em>italic words</em> reg</p>\n", @to.res.join
  end

  def accept_paragraph_plus
    assert_equal "\n<p>reg <code>teletype</code> reg</p>\n", @to.res.join
  end

  def accept_paragraph_star
    assert_equal "\n<p>reg <strong>bold</strong> reg</p>\n", @to.res.join
  end

  def accept_paragraph_underscore
    assert_equal "\n<p>reg <em>italic</em> reg</p>\n", @to.res.join
  end

  def accept_raw
    raw = <<-RAW.rstrip
<table>
<tr><th>Name<th>Count
<tr><td>a<td>1
<tr><td>b<td>2
</table>
    RAW

    assert_equal raw, @to.res.join
  end

  def accept_rule
    assert_equal "<hr style=\"height: 4px\">\n", @to.res.join
  end

  def accept_verbatim
    assert_equal "\n<pre>hi\n  world</pre>\n", @to.res.join
  end

  def end_accepting
    assert_equal 'hi', @to.end_accepting
  end

  def start_accepting
    assert_equal [], @to.res
    assert_equal [], @to.in_list_entry
    assert_equal [], @to.list
  end

  def list_nested
    expected = <<-EXPECTED
<ul><li>
<p>l1</p>
<ul><li>
<p>l1.1</p>
</li></ul>
</li><li>
<p>l2</p>
</li></ul>
    EXPECTED

    assert_equal expected, @to.res.join
  end

  def list_verbatim
    expected = <<-EXPECTED
<ul><li>
<p>list stuff</p>

<pre>* list
  with

  second

  1. indented
  2. numbered

  third

* second</pre>
</li></ul>
    EXPECTED

    assert_equal expected, @to.end_accepting
  end

  def test_accept_heading_7
    @to.start_accepting

    @to.accept_heading @RM::Heading.new(7, 'Hello')

    assert_equal "\n<h6 id=\"label-Hello\">Hello</h6>\n", @to.res.join
  end

  def test_accept_heading_aref_class
    @to.code_object = RDoc::NormalClass.new 'Foo'
    @to.start_accepting

    @to.accept_heading @RM::Heading.new(1, 'Hello')

    assert_equal "\n<h1 id=\"label-Hello\">Hello</h1>\n",
                 @to.res.join
  end

  def test_accept_heading_aref_method
    @to.code_object = RDoc::AnyMethod.new nil, 'foo'
    @to.start_accepting

    @to.accept_heading @RM::Heading.new(1, 'Hello')

    assert_equal "\n<h1 id=\"method-i-foo-label-Hello\">Hello</h1>\n",
                 @to.res.join
  end

  def test_accept_verbatim_parseable
    options = RDoc::Options.new
    rdoc = RDoc::RDoc.new
    rdoc.options = options
    RDoc::RDoc.current = rdoc

    verb = @RM::Verbatim.new("class C\n", "end\n")

    @to.start_accepting
    @to.accept_verbatim verb

    expected = <<-EXPECTED

<pre class="ruby"><span class="ruby-keyword">class</span> <span class="ruby-constant">C</span>
<span class="ruby-keyword">end</span>
</pre>
    EXPECTED

    assert_equal expected, @to.res.join
  end

  def test_accept_verbatim_parseable_error
    options = RDoc::Options.new
    rdoc = RDoc::RDoc.new
    rdoc.options = options
    RDoc::RDoc.current = rdoc

    verb = @RM::Verbatim.new("a %z'foo' # => blah\n")

    @to.start_accepting
    @to.accept_verbatim verb

    expected = <<-EXPECTED

<pre>a %z'foo' # =&gt; blah
</pre>
    EXPECTED

    assert_equal expected, @to.res.join
  end

  def test_accept_verbatim_ruby
    options = RDoc::Options.new
    rdoc = RDoc::RDoc.new
    rdoc.options = options
    RDoc::RDoc.current = rdoc

    verb = @RM::Verbatim.new("1 + 1\n")
    verb.format = :ruby

    @to.start_accepting
    @to.accept_verbatim verb

    expected = <<-EXPECTED

<pre class="ruby"><span class="ruby-value">1</span> <span class="ruby-operator">+</span> <span class="ruby-value">1</span>
</pre>
    EXPECTED

    assert_equal expected, @to.res.join
  end

  def test_convert_string
    assert_equal '&lt;&gt;', @to.convert_string('<>')
  end

  def test_convert_HYPERLINK_irc
    result = @to.convert 'irc://irc.freenode.net/#ruby-lang'

    assert_equal "\n<p><a href=\"irc://irc.freenode.net/#ruby-lang\">irc.freenode.net/#ruby-lang</a></p>\n", result
  end

  def test_convert_RDOCLINK_label_label
    result = @to.convert 'rdoc-label:label-One'

    assert_equal "\n<p><a href=\"#label-One\">One</a></p>\n", result
  end

  def test_convert_RDOCLINK_label_foottext
    result = @to.convert 'rdoc-label:foottext-1'

    assert_equal "\n<p><a href=\"#foottext-1\">*1</a></p>\n", result
  end

  def test_convert_RDOCLINK_label_footmark
    result = @to.convert 'rdoc-label:footmark-1'

    assert_equal "\n<p><a href=\"#footmark-1\">^1</a></p>\n", result
  end

  def test_convert_RDOCLINK_ref
    result = @to.convert 'rdoc-ref:C'

    assert_equal "\n<p>C</p>\n", result
  end

  def test_convert_TIDYLINK_rdoc_label
    result = @to.convert '{foo}[rdoc-label:foottext-1]'

    assert_equal "\n<p><a href=\"#foottext-1\">foo</a></p>\n", result
  end

  def test_convert_TIDYLINK_irc
    result = @to.convert '{ruby-lang}[irc://irc.freenode.net/#ruby-lang]'

    assert_equal "\n<p><a href=\"irc://irc.freenode.net/#ruby-lang\">ruby-lang</a></p>\n", result
  end

  def test_gen_url
    assert_equal '<a href="example">example</a>',
                 @to.gen_url('link:example', 'example')
  end

  def test_gen_url_rdoc_label
    assert_equal '<a href="#foottext-1">example</a>',
                 @to.gen_url('rdoc-label:foottext-1', 'example')
  end

  def test_gen_url_rdoc_label_id
    assert_equal '<a id="footmark-1" href="#foottext-1">example</a>',
                 @to.gen_url('rdoc-label:foottext-1:footmark-1', 'example')
  end

  def test_gem_url_image_url
    assert_equal '<img src="http://example.com/image.png" />', @to.gen_url('http://example.com/image.png', 'ignored')
  end

  def test_gem_url_ssl_image_url
    assert_equal '<img src="https://example.com/image.png" />', @to.gen_url('https://example.com/image.png', 'ignored')
  end

  def test_handle_special_HYPERLINK_link
    special = RDoc::Markup::Special.new 0, 'link:README.txt'

    link = @to.handle_special_HYPERLINK special

    assert_equal '<a href="README.txt">README.txt</a>', link
  end

  def test_handle_special_HYPERLINK_irc
    special = RDoc::Markup::Special.new 0, 'irc://irc.freenode.net/#ruby-lang'

    link = @to.handle_special_HYPERLINK special

    assert_equal '<a href="irc://irc.freenode.net/#ruby-lang">irc.freenode.net/#ruby-lang</a>', link
  end

  def test_list_verbatim_2
    str = "* one\n    verb1\n    verb2\n* two\n"

    expected = <<-EXPECTED
<ul><li>
<p>one</p>

<pre>verb1
verb2</pre>
</li><li>
<p>two</p>
</li></ul>
    EXPECTED

    assert_equal expected, @m.convert(str, @to)
  end

  def test_parseable_eh
    assert @to.parseable?('def x() end'),      'def'
    assert @to.parseable?('class C end'),      'class'
    assert @to.parseable?('module M end'),     'module'
    assert @to.parseable?('a # => blah'),      '=>'
    assert @to.parseable?('x { |y| ... }'),    '{ |x|'
    assert @to.parseable?('x do |y| ... end'), 'do |x|'
    refute @to.parseable?('* 1'),              '* 1'
    refute @to.parseable?('# only a comment'), '# only a comment'
    refute @to.parseable?('<% require "foo" %>'),    'ERB'
  end

  def test_to_html
    assert_equal "\n<p><code>--</code></p>\n", util_format("<tt>--</tt>")
  end

  def util_format text
    paragraph = RDoc::Markup::Paragraph.new text

    @to.start_accepting
    @to.accept_paragraph paragraph
    @to.end_accepting
  end

end

