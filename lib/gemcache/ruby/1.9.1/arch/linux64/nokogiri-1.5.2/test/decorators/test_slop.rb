require "helper"

module Nokogiri
  class TestSlop < Nokogiri::TestCase
    def test_description_tag
      doc = Nokogiri.Slop(<<-eoxml)
        <item>
          <title>foo</title>
          <description>this is the foo thing</description>
        </item>
      eoxml
      assert doc.item.title
      assert doc.item._description, 'should have description'
    end
  end
end
