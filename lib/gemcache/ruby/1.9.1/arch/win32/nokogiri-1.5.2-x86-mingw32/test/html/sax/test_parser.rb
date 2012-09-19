# -*- coding: utf-8 -*-
require "helper"

module Nokogiri
  module HTML
    module SAX
      class TestParser < Nokogiri::SAX::TestCase
        def setup
          super
          @parser = HTML::SAX::Parser.new(Doc.new)
        end

        def test_parse_empty_document
          # This caused a segfault in libxml 2.6.x
          assert_nothing_raised { @parser.parse '' }
        end

        def test_parse_empty_file
          # Make sure empty files don't break stuff
          empty_file_name =  File.join(Dir.tmpdir, 'bogus.xml')
          FileUtils.touch empty_file_name
          assert_nothing_raised { @parser.parse_file empty_file_name }
        end

        def test_parse_file
          @parser.parse_file(HTML_FILE)
          
          # Take a look at the comment in test_parse_document to know
          # a possible reason to this difference.
          if Nokogiri.uses_libxml?
            assert_equal 1110, @parser.document.end_elements.length
          else
            assert_equal 1119, @parser.document.end_elements.length
          end
        end

        def test_parse_file_nil_argument
          assert_raises(ArgumentError) {
            @parser.parse_file(nil)
          }
        end

        def test_parse_file_non_existant
          assert_raise Errno::ENOENT do
            @parser.parse_file('there_is_no_reasonable_way_this_file_exists')
          end
        end

        def test_parse_file_with_dir
          assert_raise Errno::EISDIR do
            @parser.parse_file(File.dirname(__FILE__))
          end
        end

        def test_parse_memory_nil
          assert_raise ArgumentError do
            @parser.parse_memory(nil)
          end
        end

        def test_parse_force_encoding
          @parser.parse_memory(<<-HTML, 'UTF-8')
          <meta http-equiv="Content-Type" content="text/html; charset=windows-1251">
          Информация
          HTML
          assert_equal("Информация",
                       @parser.document.data.join.strip)
        end

        def test_parse_document
          @parser.parse_memory(<<-eoxml)
            <p>Paragraph 1</p>
            <p>Paragraph 2</p>
          eoxml

          # JRuby version is different because of the internal implementation
          # JRuby version uses NekoHTML which inserts empty "head" elements.
          #
          # Currently following features are set:
          # "http://cyberneko.org/html/properties/names/elems" => "lower"
          # "http://cyberneko.org/html/properties/names/attrs" => "lower"
          if Nokogiri.uses_libxml?
            assert_equal([["html", []], ["body", []], ["p", []], ["p", []]],
                         @parser.document.start_elements)
          else
            assert_equal([["html", []], ["head", []], ["body", []], ["p", []], ["p", []]],
                         @parser.document.start_elements)
          end
        end

        def test_parser_attributes
          html = <<-eohtml
<html>
  <head>
    <title>hello</title>
  </head>
<body>
  <img src="face.jpg" title="daddy &amp; me">
  <hr noshade size="2">
</body>
</html>
          eohtml

          block_called = false
          @parser.parse(html) { |ctx|
            block_called = true
            ctx.replace_entities = true
          }

          assert block_called

          noshade_value = if Nokogiri.uses_libxml? && Nokogiri::VERSION_INFO['libxml']['loaded'] < '2.7.7'
                            ['noshade', 'noshade']
                          else
                            ['noshade', nil]
                          end

          assert_equal [
            ['html', []],
            ['head', []],
            ['title', []],
            ['body', []],
            ['img', [
                ['src', 'face.jpg'],
                ['title', 'daddy & me']
              ]],
            ['hr', [
                noshade_value,
                ['size', '2']
              ]]
          ], @parser.document.start_elements
        end
      end
    end
  end
end
