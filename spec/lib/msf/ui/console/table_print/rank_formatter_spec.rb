require 'spec_helper'

RSpec.describe Msf::Ui::Console::TablePrint::RankFormatter do
  describe 'format' do
    it 'should return the plaintext equivalent of all numerical rankings' do
      formatter = described_class.new

      expect(formatter.format(Msf::ManualRanking)).to eql Msf::RankingName[Msf::ManualRanking]
      expect(formatter.format(Msf::LowRanking)).to eql Msf::RankingName[Msf::LowRanking]
      expect(formatter.format(Msf::AverageRanking)).to eql Msf::RankingName[Msf::AverageRanking]
      expect(formatter.format(Msf::NormalRanking)).to eql Msf::RankingName[Msf::NormalRanking]
      expect(formatter.format(Msf::GoodRanking)).to eql Msf::RankingName[Msf::GoodRanking]
      expect(formatter.format(Msf::GreatRanking)).to eql Msf::RankingName[Msf::GreatRanking]
      expect(formatter.format(Msf::ExcellentRanking)).to eql Msf::RankingName[Msf::ExcellentRanking]
    end

    it 'should return an unrecognized numerical ranking unchanged' do
      formatter = described_class.new

      expect(formatter.format(42)).to eql 42
      expect(formatter.format([])).to eql []
      expect(formatter.format({})).to eql Hash.new
    end
  end
end
