require 'spec_helper'


RSpec.describe Msf::Ui::Console::TablePrint::CustomColorStyler do
  describe 'style' do
    it 'should style a given substring the given color' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5)
      styler = described_class.new({'BBB' => '%grn'})

      expect(styler.style(str)).to eql "AAAAA%grnBBB%clrAAAAA"
    end

    it 'should highlight multiple given sub-strings the given color' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5) + ('C' * 3)
      styler = described_class.new({'BBB' => '%grn', 'CCC' => '%yel'})

      expect(styler.style(str)).to eql "AAAAA%grnBBB%clrAAAAA%yelCCC%clr"
    end

    it 'should not highlight a string if it does not match exactly' do
      str = ('A' * 5) + ('B' * 3) + ('A' * 5) + ('C' * 3)
      styler = described_class.new({'BbB' => '%grn'})

      expect(styler.style(str)).to eql "AAAAABBBAAAAACCC"
    end

    it 'should highlight single characters' do
      str = 'ABCABC'
      styler = described_class.new({'A' => '%grn'})

      expect(styler.style(str)).to eql "%grnA%clrBC%grnA%clrBC"
    end

    it 'should highlight multiple substrings correctly' do
      str_first = 'BSD'
      str_second = 'OpenBSD'
      styler = described_class.new({'BSD' => '%grn', 'OpenBSD' => '%blu'})

      expect(styler.style(str_first)).to eql "%grnBSD%clr"
      expect(styler.style(str_second)).to eql "%bluOpenBSD%clr"
    end

    it 'should highlight the whole string if it is an exact match' do
      str = 'This is a long string.'
      styler = described_class.new({'This is a long string.' => '%grn'})

      expect(styler.style(str)).to eql "%grnThis is a long string.%clr"
    end
  end
end
