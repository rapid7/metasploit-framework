require "helper"

module Nokogiri
  module XML
    if RUBY_VERSION =~ /^1\.9/
      class TestDocumentEncoding < Nokogiri::TestCase
        def setup
          super
          @xml = Nokogiri::XML(File.read(XML_FILE), XML_FILE, 'UTF-8')
        end

        def test_url
          assert_equal @xml.encoding, @xml.url.encoding.name
        end

        def test_encoding
          assert_equal @xml.encoding, @xml.encoding.encoding.name
        end

        def test_dotted_version
          assert_equal 'UTF-8', Nokogiri::LIBXML_VERSION.encoding.name
        end
      end
    end
  end
end
