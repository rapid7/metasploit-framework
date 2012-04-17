require "helper"

module Nokogiri
  module XML
    class TestEntityReference < Nokogiri::TestCase
      def setup
        super
        @xml = Nokogiri::XML(File.open(XML_FILE), XML_FILE)
      end

      def test_new
        assert ref = EntityReference.new(@xml, 'ent4')
        assert_instance_of EntityReference, ref
      end

      def test_many_references
        100.times { EntityReference.new(@xml, 'foo') }
      end
    end
  end
end
