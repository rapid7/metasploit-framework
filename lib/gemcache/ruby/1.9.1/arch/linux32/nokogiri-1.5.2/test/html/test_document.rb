require "helper"

module Nokogiri
  module HTML
    class TestDocument < Nokogiri::TestCase
      def setup
        super
        @html = Nokogiri::HTML.parse(File.read(HTML_FILE))
      end

      def test_nil_css
        # Behavior is undefined but shouldn't break
        assert @html.css(nil)
        assert @html.xpath(nil)
      end

      def test_exceptions_remove_newlines
        errors = @html.errors
        assert errors.length > 0, 'has errors'
        errors.each do |error|
          assert_equal(error.to_s.chomp, error.to_s)
        end
      end

      def test_fragment
        fragment = @html.fragment
        assert_equal 0, fragment.children.length
      end

      def test_document_takes_config_block
        options = nil
        Nokogiri::HTML(File.read(HTML_FILE), HTML_FILE) do |cfg|
          options = cfg
          options.nonet.nowarning.dtdattr
        end
        assert options.nonet?
        assert options.nowarning?
        assert options.dtdattr?
      end

      def test_parse_takes_config_block
        options = nil
        Nokogiri::HTML.parse(File.read(HTML_FILE), HTML_FILE) do |cfg|
          options = cfg
          options.nonet.nowarning.dtdattr
        end
        assert options.nonet?
        assert options.nowarning?
        assert options.dtdattr?
      end

      def test_subclass
        klass = Class.new(Nokogiri::HTML::Document)
        doc = klass.new
        assert_instance_of klass, doc
      end

      def test_subclass_initialize
        klass = Class.new(Nokogiri::HTML::Document) do
          attr_accessor :initialized_with

          def initialize(*args)
            @initialized_with = args
          end
        end
        doc = klass.new("uri", "external_id", 1)
        assert_equal ["uri", "external_id", 1], doc.initialized_with
      end

      def test_subclass_dup
        klass = Class.new(Nokogiri::HTML::Document)
        doc = klass.new.dup
        assert_instance_of klass, doc
      end

      def test_subclass_parse
        klass = Class.new(Nokogiri::HTML::Document)
        doc = klass.parse(File.read(HTML_FILE))
        assert_equal @html.to_s, doc.to_s
        assert_instance_of klass, doc
      end

      def test_document_parse_method
        html = Nokogiri::HTML::Document.parse(File.read(HTML_FILE))
        assert_equal @html.to_s, html.to_s
      end

      ###
      # Nokogiri::HTML returns an empty Document when given a blank string GH#11
      def test_empty_string_returns_empty_doc
        doc = Nokogiri::HTML('')
        assert_instance_of Nokogiri::HTML::Document, doc
        assert_nil doc.root
      end

      unless Nokogiri.uses_libxml? && %w[2 6] === LIBXML_VERSION.split('.')[0..1]
        # FIXME: this is a hack around broken libxml versions
        def test_to_xhtml_with_indent
          doc = Nokogiri::HTML('<html><body><a>foo</a></body></html>')
          doc = Nokogiri::HTML(doc.to_xhtml(:indent => 2))
          assert_indent 2, doc
        end

        def test_write_to_xhtml_with_indent
          io = StringIO.new
          doc = Nokogiri::HTML('<html><body><a>foo</a></body></html>')
          doc.write_xhtml_to io, :indent => 5
          io.rewind
          doc = Nokogiri::HTML(io.read)
          assert_indent 5, doc
        end
      end

      def test_swap_should_not_exist
        assert_raises(NoMethodError) {
          @html.swap
        }
      end

      def test_namespace_should_not_exist
        assert_raises(NoMethodError) {
          @html.namespace
        }
      end

      def test_meta_encoding
        assert_equal 'UTF-8', @html.meta_encoding

        html = Nokogiri::HTML(<<-eohtml)
<html>
  <head>
    <meta http-equiv="X-Content-Type" content="text/html; charset=Shift_JIS">
  </head>
  <body>
    foo
  </body>
</html>
        eohtml
        assert_nil html.meta_encoding
      end

      def test_meta_encoding=
        @html.meta_encoding = 'EUC-JP'
        assert_equal 'EUC-JP', @html.meta_encoding
      end

      def test_title
        assert_equal 'Tender Lovemaking  ', @html.title
        doc = Nokogiri::HTML('<html><body>foo</body></html>')
        assert_nil doc.title
      end

      def test_title=()
        doc = Nokogiri::HTML(<<eohtml)
<html>
  <head>
    <title>old</title>
  </head>
  <body>
    foo
  </body>
</html>
eohtml
        doc.title = 'new'
        assert_equal 'new', doc.title

        doc = Nokogiri::HTML(<<eohtml)
<html>
  <head>
  </head>
  <body>
    foo
  </body>
</html>
eohtml
        doc.title = 'new'
        assert_equal 'new', doc.title

        doc = Nokogiri::HTML(<<eohtml)
<html>
  <body>
    foo
  </body>
</html>
eohtml
        doc.title = 'new'
        if Nokogiri.uses_libxml?
          assert_nil doc.title
        else
          assert_equal 'new', doc.title
        end
      end

      def test_meta_encoding_without_head
        html = Nokogiri::HTML('<html><body>foo</body></html>')
        assert_nil html.meta_encoding

        html.meta_encoding = 'EUC-JP'
        assert_nil html.meta_encoding
      end

      def test_meta_encoding_with_empty_content_type
        html = Nokogiri::HTML(<<-eohtml)
<html>
  <head>
    <meta http-equiv="Content-Type" content="">
  </head>
  <body>
    foo
  </body>
</html>
        eohtml
        assert_nil html.meta_encoding

        html = Nokogiri::HTML(<<-eohtml)
<html>
  <head>
    <meta http-equiv="Content-Type">
  </head>
  <body>
    foo
  </body>
</html>
        eohtml
        assert_nil html.meta_encoding
      end

      def test_root_node_parent_is_document
        parent = @html.root.parent
        assert_equal @html, parent
        assert_instance_of Nokogiri::HTML::Document, parent
      end

      def test_parse_handles_nil_gracefully
        assert_nothing_raised do
          @doc = Nokogiri::HTML::Document.parse(nil)
        end
        assert_instance_of Nokogiri::HTML::Document, @doc
      end

      def test_parse_empty_document
        doc = Nokogiri::HTML("\n")
        assert_equal 0, doc.css('a').length
        assert_equal 0, doc.xpath('//a').length
        assert_equal 0, doc.search('//a').length
      end

      def test_HTML_function
        html = Nokogiri::HTML(File.read(HTML_FILE))
        assert html.html?
      end

      def test_parse_io
        assert File.open(HTML_FILE, 'rb') { |f|
          Document.read_io(f, nil, 'UTF-8',
                           XML::ParseOptions::NOERROR | XML::ParseOptions::NOWARNING
                          )
        }
      end

      def test_parse_temp_file
        temp_html_file = Tempfile.new("TEMP_HTML_FILE")
        File.open(HTML_FILE, 'rb') { |f| temp_html_file.write f.read }
        temp_html_file.close
        temp_html_file.open
        assert_equal Nokogiri::HTML.parse(File.read(HTML_FILE)).xpath('//div/a').length, 
          Nokogiri::HTML.parse(temp_html_file).xpath('//div/a').length
      end

      def test_to_xhtml
        assert_match 'XHTML', @html.to_xhtml
        assert_match 'XHTML', @html.to_xhtml(:encoding => 'UTF-8')
        assert_match 'UTF-8', @html.to_xhtml(:encoding => 'UTF-8')
      end

      def test_no_xml_header
        html = Nokogiri::HTML(<<-eohtml)
        <html>
        </html>
        eohtml
        assert html.to_html.length > 0, 'html length is too short'
        assert_no_match(/^<\?xml/, html.to_html)
      end

      def test_document_has_error
        html = Nokogiri::HTML(<<-eohtml)
        <html>
          <body>
            <div awesome="asdf>
              <p>inside div tag</p>
            </div>
            <p>outside div tag</p>
          </body>
        </html>
        eohtml
        assert html.errors.length > 0
      end

      def test_relative_css
        html = Nokogiri::HTML(<<-eohtml)
        <html>
          <body>
            <div>
              <p>inside div tag</p>
            </div>
            <p>outside div tag</p>
          </body>
        </html>
        eohtml
        set = html.search('div').search('p')
        assert_equal(1, set.length)
        assert_equal('inside div tag', set.first.inner_text)
      end

      def test_multi_css
        html = Nokogiri::HTML(<<-eohtml)
        <html>
          <body>
            <div>
              <p>p tag</p>
              <a>a tag</a>
            </div>
          </body>
        </html>
        eohtml
        set = html.css('p, a')
        assert_equal(2, set.length)
        assert_equal ['a tag', 'p tag'].sort, set.map { |x| x.content }.sort
      end

      def test_inner_text
        html = Nokogiri::HTML(<<-eohtml)
        <html>
          <body>
            <div>
              <p>
                Hello world!
              </p>
            </div>
          </body>
        </html>
        eohtml
        node = html.xpath('//div').first
        assert_equal('Hello world!', node.inner_text.strip)
      end

      def test_find_by_xpath
        found = @html.xpath('//div/a')
        assert_equal 3, found.length
      end

      def test_find_by_css
        found = @html.css('div > a')
        assert_equal 3, found.length
      end

      def test_find_by_css_with_square_brackets
        found = @html.css("div[@id='header'] > h1")
        found = @html.css("div[@id='header'] h1") # this blows up on commit 6fa0f6d329d9dbf1cc21c0ac72f7e627bb4c05fc
        assert_equal 1, found.length
      end

      def test_find_with_function
        assert @html.css("div:awesome() h1", Class.new {
          def awesome divs
            [divs.first]
          end
        }.new)
      end

      def test_dup_shallow
        found = @html.search('//div/a').first
        dup = found.dup(0)
        assert dup
        assert_equal '', dup.content
      end

      def test_search_can_handle_xpath_and_css
        found = @html.search('//div/a', 'div > p')
        length = @html.xpath('//div/a').length +
          @html.css('div > p').length
        assert_equal length, found.length
      end

      def test_dup_document
        assert dup = @html.dup
        assert_not_equal dup, @html
        assert @html.html?
        assert_instance_of Nokogiri::HTML::Document, dup
        assert dup.html?, 'duplicate should be html'
        assert_equal @html.to_s, dup.to_s
      end

      def test_dup_document_shallow
        assert dup = @html.dup(0)
        assert_not_equal dup, @html
      end

      def test_dup
        found = @html.search('//div/a').first
        dup = found.dup
        assert dup
        assert_equal found.content, dup.content
        assert_equal found.document, dup.document
      end

      def test_inner_html
        html = Nokogiri::HTML(<<-eohtml)
        <html>
          <body>
            <div>
              <p>
                Hello world!
              </p>
            </div>
          </body>
        </html>
        eohtml
        node = html.xpath('//div').first
        assert_equal('<p>Helloworld!</p>', node.inner_html.gsub(/\s/, ''))
      end

      def test_round_trip
        doc = Nokogiri::HTML(@html.inner_html)
        assert_equal @html.root.to_html, doc.root.to_html
      end

      def test_fragment_contains_text_node
        fragment = Nokogiri::HTML.fragment('fooo')
        assert_equal 1, fragment.children.length
        assert_equal 'fooo', fragment.inner_text
      end

      def test_fragment_includes_two_tags
        assert_equal 2, Nokogiri::HTML.fragment("<br/><hr/>").children.length
      end

      def test_relative_css_finder
        doc = Nokogiri::HTML(<<-eohtml)
          <html>
            <body>
              <div class="red">
                <p>
                  inside red
                </p>
              </div>
              <div class="green">
                <p>
                  inside green
                </p>
              </div>
            </body>
          </html>
        eohtml
        red_divs = doc.css('div.red')
        assert_equal 1, red_divs.length
        p_tags = red_divs.first.css('p')
        assert_equal 1, p_tags.length
        assert_equal 'inside red', p_tags.first.text.strip
      end

      def test_find_classes
        doc = Nokogiri::HTML(<<-eohtml)
          <html>
            <body>
              <p class="red">RED</p>
              <p class="awesome red">RED</p>
              <p class="notred">GREEN</p>
              <p class="green notred">GREEN</p>
            </body>
          </html>
        eohtml
        list = doc.css('.red')
        assert_equal 2, list.length
        assert_equal %w{ RED RED }, list.map { |x| x.text }
      end

      def test_parse_can_take_io
        html = nil
        File.open(HTML_FILE, 'rb') { |f|
          html = Nokogiri::HTML(f)
        }
        assert html.html?
      end

      def test_html?
        assert !@html.xml?
        assert @html.html?
      end

      def test_serialize
        assert @html.serialize
        assert @html.to_html
      end
    end
  end
end

