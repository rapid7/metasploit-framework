require "helper"

module Nokogiri
  module XML
    class TestComment < Nokogiri::TestCase
      def setup
        super
        @xml = Nokogiri::XML.parse(File.read(XML_FILE), XML_FILE)
      end

      def test_new
        comment = Nokogiri::XML::Comment.new(@xml, 'hello world')
        assert_equal('<!--hello world-->', comment.to_s)
      end

      def test_comment?
        comment = Nokogiri::XML::Comment.new(@xml, 'hello world')
        assert(comment.comment?)
        assert(!@xml.root.comment?)
      end

      def test_many_comments
        100.times {
          Nokogiri::XML::Comment.new(@xml, 'hello world')
        }
      end
    end
  end
end
