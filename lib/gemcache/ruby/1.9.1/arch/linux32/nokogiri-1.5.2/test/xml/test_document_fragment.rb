require "helper"

module Nokogiri
  module XML
    class TestDocumentFragment < Nokogiri::TestCase
      def setup
        super
        @xml = Nokogiri::XML.parse(File.read(XML_FILE), XML_FILE)
      end

      def test_fragment_is_relative
        doc      = Nokogiri::XML('<root><a xmlns="blah" /></root>')
        ctx      = doc.root.child
        fragment = Nokogiri::XML::DocumentFragment.new(doc, '<hello />', ctx)
        hello    = fragment.child

        assert_equal 'hello', hello.name
        assert_equal doc.root.child.namespace, hello.namespace
      end

      def test_node_fragment_is_relative
        doc      = Nokogiri::XML('<root><a xmlns="blah" /></root>')
        assert doc.root.child
        fragment = doc.root.child.fragment('<hello />')
        hello    = fragment.child

        assert_equal 'hello', hello.name
        assert_equal doc.root.child.namespace, hello.namespace
      end

      def test_new
        assert Nokogiri::XML::DocumentFragment.new(@xml)
      end

      def test_fragment_should_have_document
        fragment = Nokogiri::XML::DocumentFragment.new(@xml)
        assert_equal @xml, fragment.document
      end

      def test_name
        fragment = Nokogiri::XML::DocumentFragment.new(@xml)
        assert_equal '#document-fragment', fragment.name
      end

      def test_static_method
        fragment = Nokogiri::XML::DocumentFragment.parse("<div>a</div>")
        assert_instance_of Nokogiri::XML::DocumentFragment, fragment
      end

      def test_static_method_with_namespaces
        # follows different path in FragmentHandler#start_element which blew up after 597195ff
        fragment = Nokogiri::XML::DocumentFragment.parse("<o:div>a</o:div>")
        assert_instance_of Nokogiri::XML::DocumentFragment, fragment
      end

      def test_many_fragments
        100.times { Nokogiri::XML::DocumentFragment.new(@xml) }
      end

      def test_subclass
        klass = Class.new(Nokogiri::XML::DocumentFragment)
        fragment = klass.new(@xml, "<div>a</div>")
        assert_instance_of klass, fragment
      end

      def test_subclass_parse
        klass = Class.new(Nokogiri::XML::DocumentFragment)
        doc = klass.parse("<div>a</div>")
        assert_instance_of klass, doc
      end

      def test_xml_fragment
        fragment = Nokogiri::XML.fragment("<div>a</div>")
        assert_equal "<div>a</div>", fragment.to_s
      end

      def test_xml_fragment_has_multiple_toplevel_children
        doc = "<div>b</div><div>e</div>"
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "<div>b</div><div>e</div>", fragment.to_s
      end

      def test_xml_fragment_has_outer_text
        # this test is descriptive, not prescriptive.
        doc = "a<div>b</div>"
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "a<div>b</div>", fragment.to_s

        doc = "<div>b</div>c"
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "<div>b</div>c", fragment.to_s
      end

      def test_xml_fragment_case_sensitivity
        doc = "<crazyDiv>b</crazyDiv>"
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "<crazyDiv>b</crazyDiv>", fragment.to_s
      end

      def test_xml_fragment_with_leading_whitespace
        doc = "     <div>b</div>  "
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "     <div>b</div>  ", fragment.to_s
      end

      def test_xml_fragment_with_leading_whitespace_and_newline
        doc = "     \n<div>b</div>  "
        fragment = Nokogiri::XML::Document.new.fragment(doc)
        assert_equal "     \n<div>b</div>  ", fragment.to_s
      end

      def test_fragment_children_search
        fragment = Nokogiri::XML::Document.new.fragment(
          '<div><p id="content">hi</p></div>'
        )
        css     = fragment.children.css('p')
        xpath   = fragment.children.xpath('.//p')
        assert_equal css, xpath
      end

      def test_fragment_search
        frag = Nokogiri::XML::Document.new.fragment '<p id="content">hi</p>'

        p_tag = frag.css('#content').first
        assert_equal 'p', p_tag.name

        assert_equal p_tag, frag.xpath('./*[@id = \'content\']').first
      end

      def test_fragment_without_a_namespace_does_not_get_a_namespace
        doc = Nokogiri::XML <<-EOX
          <root xmlns="http://tenderlovemaking.com/" xmlns:foo="http://flavorjon.es/" xmlns:bar="http://google.com/">
            <foo:existing></foo:existing>
          </root>
        EOX
        frag = doc.fragment "<newnode></newnode>"
        assert_nil frag.namespace
      end

      def test_fragment_namespace_resolves_against_document_root
        doc = Nokogiri::XML <<-EOX
          <root xmlns:foo="http://flavorjon.es/" xmlns:bar="http://google.com/">
            <foo:existing></foo:existing>
          </root>
        EOX
        ns = doc.root.namespace_definitions.detect { |x| x.prefix == "bar" }

        frag = doc.fragment "<bar:newnode></bar:newnode>"
        assert frag.children.first.namespace
        assert_equal ns, frag.children.first.namespace
      end

      def test_fragment_invalid_namespace_is_silently_ignored
        doc = Nokogiri::XML <<-EOX
          <root xmlns:foo="http://flavorjon.es/" xmlns:bar="http://google.com/">
            <foo:existing></foo:existing>
          </root>
        EOX
        frag = doc.fragment "<baz:newnode></baz:newnode>"
        assert_nil frag.children.first.namespace
      end

      def test_decorator_is_applied
        x = Module.new do
          def awesome!
          end
        end
        util_decorate(@xml, x)
        fragment = Nokogiri::XML::DocumentFragment.new(@xml, "<div>a</div><div>b</div>")

        assert node_set = fragment.css('div')
        assert node_set.respond_to?(:awesome!)
        node_set.each do |node|
          assert node.respond_to?(:awesome!), node.class
        end
        assert fragment.children.respond_to?(:awesome!), fragment.children.class
      end

      def test_for_libxml_in_context_fragment_parsing_bug_workaround
        10.times do
          begin
            fragment = Nokogiri::XML.fragment("<div></div>")
            parent = fragment.children.first
            child = parent.parse("<h1></h1>").first
            parent.add_child child
          end
          GC.start
        end
      end
    end
  end
end
