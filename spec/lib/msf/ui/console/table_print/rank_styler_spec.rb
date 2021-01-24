require 'spec_helper'

RSpec.describe Msf::Ui::Console::TablePrint::RankStyler do
  describe 'style' do
    it 'should color all ranks above Good green' do
      str1 = Msf::RankingName[Msf::GreatRanking]
      str2 = Msf::RankingName[Msf::ExcellentRanking]
      styler = described_class.new

      expect(styler.style(str1)).to eql "%grngreat%clr"
      expect(styler.style(str2)).to eql "%grnexcellent%clr"
    end


    it 'should return all ranks below Good unchanged' do
      str1 = Msf::RankingName[Msf::ManualRanking]
      str2 = Msf::RankingName[Msf::LowRanking]
      str3 = Msf::RankingName[Msf::AverageRanking ]
      str4 = Msf::RankingName[Msf::NormalRanking]
      str5 = Msf::RankingName[Msf::GoodRanking]
      styler = described_class.new

      expect(styler.style(str1)).to eql str1
      expect(styler.style(str2)).to eql str2
      expect(styler.style(str3)).to eql str3
      expect(styler.style(str4)).to eql str4
      expect(styler.style(str5)).to eql str5
    end
  end


end
