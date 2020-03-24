require 'spec_helper'

require 'msf/ui/console/table_print/highlight_substring_styler'

RSpec.describe Msf::Ui::Console::TablePrint::HighlightSubstringStyler do
  describe 'style' do
    it 'should highlight a given sub-string magenta' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5)
      styler = described_class.new(['BBB'])

      expect(styler.style(str)).to eql "AAAAA%bgmagBBB%clrAAAAA"
    end

    it 'should highlight a multiple given sub-strings magenta' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5) + ('C' * 3)
      styler = described_class.new(%w(BBB CCC))

      expect(styler.style(str)).to eql "AAAAA%bgmagBBB%clrAAAAA%bgmagCCC%clr"
    end

    it 'should highlight a multiple given sub-strings magenta regardless of case' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5) + ('C' * 3)
      styler = described_class.new(%w(BbB ccC))

      expect(styler.style(str)).to eql "AAAAA%bgmagBBB%clrAAAAA%bgmagCCC%clr"
    end
  end
end
