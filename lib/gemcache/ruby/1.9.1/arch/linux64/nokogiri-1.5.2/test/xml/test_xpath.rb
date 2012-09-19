require "helper"

module Nokogiri
  module XML
    class TestXPath < Nokogiri::TestCase

      # ** WHY ALL THOSE _if Nokogiri.uses_libxml?_ **
      # Hi, my dear readers,
      #
      # After reading these tests you may be wondering why all those ugly
      # if Nokogiri.uses_libxml? sparsed over the whole document. Well, let
      # me explain it. While using XPath in Java, you need the extension
      # functions to be in a namespace. This is not required by XPath, afaik,
      # but it is an usual convention though.
      #
      # Furthermore, CSS does not support extension functions but it does in
      # Nokogiri. Result: you cannot use them in JRuby impl. At least, until
      # the CSS to XPath parser is patched, and let me say that there are more
      # important features to add before that happens. I hope you will forgive
      # me.
      #
      # Yours truly,
      #
      # The guy whose headaches belong to Nokogiri JRuby impl.


      def setup
        super

        @xml = Nokogiri::XML.parse(File.read(XML_FILE), XML_FILE)

        @ns = @xml.root.namespaces

        # TODO: Maybe I should move this to the original code.
        @ns["nokogiri"] = "http://www.nokogiri.org/default_ns/ruby/extensions_functions"

        @handler = Class.new {
          attr_reader :things

          def initialize
            @things = []
          end

          def thing thing
            @things << thing
            thing
          end

          def returns_array node_set
            @things << node_set.to_a
            node_set.to_a
          end

          def my_filter set, attribute, value
            set.find_all { |x| x[attribute] == value }
          end

          def saves_node_set node_set
            @things = node_set
          end

          def value
            123.456
          end
        }.new
      end

      def test_variable_binding
        assert_equal 4, @xml.xpath('//address[@domestic=$value]', nil, :value => 'Yes').length
      end

      def test_unknown_attribute
        assert_equal 0, @xml.xpath('//employee[@id="asdfasdf"]/@fooo').length
        assert_nil @xml.xpath('//employee[@id="asdfasdf"]/@fooo')[0]
      end

      def test_boolean
        assert_equal false, @xml.xpath('1 = 2')
      end

      def test_number
        assert_equal 2, @xml.xpath('1 + 1')
      end

      def test_string
        assert_equal 'foo', @xml.xpath('concat("fo", "o")')
      end

      def test_css_search_uses_custom_selectors_with_arguments
        set = if Nokogiri.uses_libxml?
                @xml.css('employee > address:my_filter("domestic", "Yes")', @handler)
              else
                @xml.xpath("//employee/address[nokogiri:my_filter(., \"domestic\", \"Yes\")]", @ns, @handler)
               end
        assert set.length > 0
        set.each do |node|
          assert_equal 'Yes', node['domestic']
        end
      end

      def test_css_search_uses_custom_selectors
        set = @xml.xpath('//employee')
        assert_nothing_raised do
          if Nokogiri.uses_libxml?
            @xml.css('employee:thing()', @handler)
          else
            @xml.xpath("//employee[nokogiri:thing(.)]", @ns, @handler)
          end
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal(set.to_a, @handler.things.flatten)
      end

      def test_pass_self_to_function
        set = if Nokogiri.uses_libxml?
                @xml.xpath('//employee/address[my_filter(., "domestic", "Yes")]', @handler)
              else
                @xml.xpath('//employee/address[nokogiri:my_filter(., "domestic", "Yes")]', @ns, @handler)
              end
        assert set.length > 0
        set.each do |node|
          assert_equal 'Yes', node['domestic']
        end
      end

      def test_custom_xpath_function_gets_strings
        set = @xml.xpath('//employee')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[thing("asdf")]', @handler)
        else
          @xml.xpath('//employee[nokogiri:thing("asdf")]', @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal(['asdf'] * set.length, @handler.things)
      end

      def test_custom_xpath_function_returns_string
        if Nokogiri.uses_libxml?
          result = @xml.xpath('thing("asdf")', @handler)
        else
          result = @xml.xpath('nokogiri:thing("asdf")', @ns, @handler)
        end
        assert_equal 'asdf', result
      end

      def test_custom_xpath_gets_true_booleans
        set = @xml.xpath('//employee')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[thing(true())]', @handler)
        else
          @xml.xpath("//employee[nokogiri:thing(true())]", @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal([true] * set.length, @handler.things)
      end

      def test_custom_xpath_gets_false_booleans
        set = @xml.xpath('//employee')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[thing(false())]', @handler)
        else
          @xml.xpath("//employee[nokogiri:thing(false())]", @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal([false] * set.length, @handler.things)
      end

      def test_custom_xpath_gets_numbers
        set = @xml.xpath('//employee')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[thing(10)]', @handler)
        else
          @xml.xpath('//employee[nokogiri:thing(10)]', @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal([10] * set.length, @handler.things)
      end

      def test_custom_xpath_gets_node_sets
        set = @xml.xpath('//employee/name')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[thing(name)]', @handler)
        else
          @xml.xpath('//employee[nokogiri:thing(name)]', @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal(set.to_a, @handler.things.flatten)
      end

      def test_custom_xpath_gets_node_sets_and_returns_array
        set = @xml.xpath('//employee/name')
        if Nokogiri.uses_libxml?
          @xml.xpath('//employee[returns_array(name)]', @handler)
        else
          @xml.xpath('//employee[nokogiri:returns_array(name)]', @ns, @handler)
        end
        assert_equal(set.length, @handler.things.length)
        assert_equal(set.to_a, @handler.things.flatten)
      end

      def test_custom_xpath_handler_is_passed_a_decorated_node_set
        x = Module.new do
          def awesome! ; end
        end
        util_decorate(@xml, x)

        assert @xml.xpath('//employee/name')

        @xml.xpath('//employee[saves_node_set(name)]', @handler)
        assert_equal @xml, @handler.things.document
        assert @handler.things.respond_to?(:awesome!)
      end

      def test_code_that_invokes_OP_RESET_inside_libxml2
        doc = "<html><body id='foo'><foo>hi</foo></body></html>"
        xpath = 'id("foo")//foo'
        nokogiri = Nokogiri::HTML.parse(doc)
        assert nokogiri.xpath(xpath)
      end

      def test_custom_xpath_handler_with_args_under_gc_pressure
        # see http://github.com/tenderlove/nokogiri/issues/#issue/345
        tool_inspector = Class.new do
          def name_equals(nodeset, name, *args)
            nodeset.all? do |node|
              args.each { |thing| thing.inspect }
              node["name"] == name
            end
          end
        end.new

        xml = <<-EOXML
          <toolbox>
            #{"<tool name='hammer'/><tool name='wrench'/>" * 10}
          </toolbox>
        EOXML
        doc = Nokogiri::XML xml

        # long list of long arguments, to apply GC pressure during
        # ruby_funcall argument marshalling
        xpath = ["//tool[name_equals(.,'hammer'"]
        1000.times { xpath << "'unused argument #{'x' * 1000}'" }
        xpath << "'unused argument')]"
        xpath = xpath.join(',')

        assert_equal doc.xpath("//tool[@name='hammer']"), doc.xpath(xpath, tool_inspector)
      end

      def test_custom_xpath_without_arguments
        if Nokogiri.uses_libxml?
          value = @xml.xpath('value()', @handler)
        else
          value = @xml.xpath('nokogiri:value()', @ns, @handler)
        end
        assert_equal 123.456, value
      end
    end
  end
end
