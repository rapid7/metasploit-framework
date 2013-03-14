require "helper"

module Nokogiri
  module XML
    class TestNamespace < Nokogiri::TestCase
      def setup
        super
        @xml = Nokogiri::XML <<-eoxml
          <root xmlns="http://tenderlovemaking.com/" xmlns:foo="bar">
            <awesome/>
          </root>
        eoxml
      end

      if Nokogiri.uses_libxml?
        def test_namespace_is_in_node_cache
          node = @xml.root.namespace
          assert @xml.instance_variable_get(:@node_cache).include?(node)
        end
      end

      def test_built_nodes_keep_namespace_decls
        doc = Document.new
        e   = Node.new 'element', doc
        c   = Node.new 'child', doc
        c.default_namespace = 'woop:de:doo'

        assert c.namespace, 'has a namespace'
        e.add_child c
        assert c.namespace, 'has a namespace'

        doc.add_child e
        assert c.namespace, 'has a namespace'
      end

      def test_inspect
        ns = @xml.root.namespace
        assert_equal "#<#{ns.class.name}:#{sprintf("0x%x", ns.object_id)} href=#{ns.href.inspect}>", ns.inspect
      end

      def test_namespace_node_prefix
        namespaces = @xml.root.namespace_definitions
        assert_equal [nil, 'foo'], namespaces.map { |x| x.prefix }
      end

      def test_namespace_node_href
        namespaces = @xml.root.namespace_definitions
        assert_equal [
          'http://tenderlovemaking.com/',
          'bar'
        ], namespaces.map { |x| x.href }
      end

      def test_equality
        namespaces = @xml.root.namespace_definitions
        assert_equal namespaces, @xml.root.namespace_definitions
      end

      def test_add_definition
        @xml.root.add_namespace_definition('baz', 'bar')
        assert_equal 3, @xml.root.namespace_definitions.length
      end

      def test_add_definition_return
        ns = @xml.root.add_namespace_definition('baz', 'bar')
        assert_equal 'baz', ns.prefix
      end

      def test_remove_entity_namespace
        s = %q{<?xml version='1.0'?><!DOCTYPE schema PUBLIC "-//W3C//DTD XMLSCHEMA 200102//EN" "XMLSchema.dtd" [<!ENTITY % p ''>]>}
        Nokogiri::XML(s).remove_namespaces!
      end
    end
  end
end
