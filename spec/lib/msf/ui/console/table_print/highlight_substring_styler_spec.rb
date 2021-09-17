require 'spec_helper'


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

    it 'should highlight single characters' do
      str = 'ABCABC'
      styler = described_class.new(%w(a b c))

      expect(styler.style(str)).to eql "%bgmagA%clr%bgmagB%clr%bgmagC%clr%bgmagA%clr%bgmagB%clr%bgmagC%clr"
    end

    it 'should support regex highlight terms' do
      str = 'username password compassionate PASSWORD foo bar'
      styler = described_class.new([/user|pass/, 'foo'])

      expect(styler.style(str)).to eql "%bgmaguser%clrname %bgmagpass%clrword com%bgmagpass%clrionate PASSWORD %bgmagfoo%clr bar"
    end
  end
end
