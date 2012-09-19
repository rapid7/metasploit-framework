require "helper"

module Nokogiri
  module XML
    class TestDTD < Nokogiri::TestCase
      def setup
        super
        @xml = Nokogiri::XML(File.open(XML_FILE))
        assert @dtd = @xml.internal_subset
      end

      def test_system_id
        assert_equal 'staff.dtd', @dtd.system_id
      end

      def test_external_id
        if Nokogiri.uses_libxml?
          xml = Nokogiri::XML('<!DOCTYPE foo PUBLIC "bar"><foo />')
        else
          xml = Nokogiri::XML('<!DOCTYPE foo PUBLIC "bar" ""><foo />')
        end
        assert dtd = xml.internal_subset
        assert_equal 'bar', dtd.external_id
      end

      def test_content
        assert_raise NoMethodError do
          @dtd.content
        end
      end

      def test_empty_attributes
        dtd = Nokogiri::HTML("<html></html>").internal_subset
        assert_equal Hash.new, dtd.attributes
      end

      def test_attributes
        assert_equal ['width'], @dtd.attributes.keys
        assert_equal '0', @dtd.attributes['width'].default
      end

      def test_keys
        assert_equal ['width'], @dtd.keys
      end

      def test_each
        hash = {}
        @dtd.each { |key, value| hash[key] = value }
        assert_equal @dtd.attributes, hash
      end

      def test_namespace
        assert_raise NoMethodError do
          @dtd.namespace
        end
      end

      def test_namespace_definitions
        assert_raise NoMethodError do
          @dtd.namespace_definitions
        end
      end

      def test_line
        assert_raise NoMethodError do
          @dtd.line
        end
      end

      def test_validate
        if Nokogiri.uses_libxml?
          list = @xml.internal_subset.validate @xml
          assert_equal 44, list.length
        else
          xml = Nokogiri::XML(File.open(XML_FILE)) {|cfg| cfg.dtdvalid}
          list = xml.internal_subset.validate xml
          assert_equal 37, list.length
        end
      end

      def test_external_subsets
        assert subset = @xml.internal_subset
        assert_equal 'staff', subset.name
      end

      def test_entities
        assert entities = @dtd.entities
        assert_equal %w[ ent1 ent2 ent3 ent4 ent5 ].sort, entities.keys.sort
      end

      def test_elements
        assert elements = @dtd.elements
        assert_equal %w[ br ], elements.keys
        assert_equal 'br', elements['br'].name
      end

      def test_notations
        assert notations = @dtd.notations
        assert_equal %w[ notation1 notation2 ].sort, notations.keys.sort
        assert notation1 = notations['notation1']
        assert_equal 'notation1', notation1.name
        assert_equal 'notation1File', notation1.public_id
        assert_nil notation1.system_id
      end
    end
  end
end
