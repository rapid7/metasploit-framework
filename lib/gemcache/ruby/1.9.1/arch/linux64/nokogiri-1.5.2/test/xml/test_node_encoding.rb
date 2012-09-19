require "helper"

module Nokogiri
  module XML
    if RUBY_VERSION =~ /^1\.9/
      class TestNodeEncoding < Nokogiri::TestCase
        def setup
          super
          @html = Nokogiri::HTML(File.read(HTML_FILE), HTML_FILE)
        end

        def test_get_attribute
          node = @html.css('a').first
          assert_equal @html.encoding, node['href'].encoding.name
        end

        def test_text_encoding_is_utf_8
          @html = Nokogiri::HTML(File.open(NICH_FILE))
          assert_equal 'UTF-8', @html.text.encoding.name
        end

        def test_serialize_encoding_html
          @html = Nokogiri::HTML(File.open(NICH_FILE))
          assert_equal @html.encoding.downcase,
            @html.serialize.encoding.name.downcase

          @doc = Nokogiri::HTML(@html.serialize)
          assert_equal @html.serialize, @doc.serialize
        end

        def test_serialize_encoding_xml
          @xml = Nokogiri::XML(File.open(SHIFT_JIS_XML))
          assert_equal @xml.encoding.downcase,
            @xml.serialize.encoding.name.downcase

          @doc = Nokogiri::XML(@xml.serialize)
          assert_equal @xml.serialize, @doc.serialize
        end

        def test_encode_special_chars
          foo = @html.css('a').first.encode_special_chars('foo')
          assert_equal @html.encoding, foo.encoding.name
        end

        def test_content
          node = @html.css('a').first
          assert_equal @html.encoding, node.content.encoding.name
        end

        def test_name
          node = @html.css('a').first
          assert_equal @html.encoding, node.name.encoding.name
        end

        def test_path
          node = @html.css('a').first
          assert_equal @html.encoding, node.path.encoding.name
        end

        def test_namespace
          xml = <<-eoxml
<root>
 <car xmlns:part="http://general-motors.com/">
  <part:tire>Michelin Model XGV</part:tire>
 </car>
 <bicycle xmlns:part="http://schwinn.com/">
  <part:tire>I'm a bicycle tire!</part:tire>
 </bicycle>
</root>
          eoxml
          doc = Nokogiri::XML(xml, nil, 'UTF-8')
          assert_equal 'UTF-8', doc.encoding
          n = doc.xpath('//part:tire', { 'part' => 'http://schwinn.com/' }).first
          assert n
          assert_equal doc.encoding, n.namespace.href.encoding.name
          assert_equal doc.encoding, n.namespace.prefix.encoding.name
        end

        def test_namespace_as_hash
          xml = <<-eoxml
<root>
 <car xmlns:part="http://general-motors.com/">
  <part:tire>Michelin Model XGV</part:tire>
 </car>
 <bicycle xmlns:part="http://schwinn.com/">
  <part:tire>I'm a bicycle tire!</part:tire>
 </bicycle>
</root>
          eoxml
          doc = Nokogiri::XML(xml, nil, 'UTF-8')
          assert_equal 'UTF-8', doc.encoding
          assert n = doc.xpath('//car').first

          n.namespace_definitions.each do |nd|
            assert_equal doc.encoding, nd.href.encoding.name
            assert_equal doc.encoding, nd.prefix.encoding.name
          end

          n.namespaces.each do |k,v|
            assert_equal doc.encoding, k.encoding.name
            assert_equal doc.encoding, v.encoding.name
          end
        end
      end
    end
  end
end
