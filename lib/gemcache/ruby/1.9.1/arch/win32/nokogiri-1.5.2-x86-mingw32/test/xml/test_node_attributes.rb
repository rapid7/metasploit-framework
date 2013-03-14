require "helper"

module Nokogiri
  module XML
    class TestNodeAttributes < Nokogiri::TestCase
      def test_attribute_with_ns
        doc = Nokogiri::XML <<-eoxml
          <root xmlns:tlm='http://tenderlovemaking.com/'>
            <node tlm:foo='bar' foo='baz' />
          </root>
        eoxml

        node = doc.at('node')

        assert_equal 'bar',
          node.attribute_with_ns('foo', 'http://tenderlovemaking.com/').value
      end

      def test_namespace_key?
        doc = Nokogiri::XML <<-eoxml
          <root xmlns:tlm='http://tenderlovemaking.com/'>
            <node tlm:foo='bar' foo='baz' />
          </root>
        eoxml

        node = doc.at('node')

        assert node.namespaced_key?('foo', 'http://tenderlovemaking.com/')
        assert node.namespaced_key?('foo', nil)
        assert !node.namespaced_key?('foo', 'foo')
      end

      def test_set_attribute_frees_nodes # testing a segv
        skip("JRuby doesn't do GC.") if Nokogiri.jruby?
        document = Nokogiri::XML.parse("<foo></foo>")

        node = document.root
        node['visible'] = 'foo'
        attribute = node.attribute('visible')
        text = Nokogiri::XML::Text.new 'bar', document
        attribute.add_child(text)

        begin
          gc_previous = GC.stress
          GC.stress = true
          node['visible'] = 'attr'
        ensure
          GC.stress = gc_previous
        end
      end
    end
  end
end
