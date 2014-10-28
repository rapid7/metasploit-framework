RSpec.describe Msf::HostState do
  context 'CONSTANTS' do
    context 'Alive' do
      subject(:alive)  {
        described_class::Alive
      }

      it { is_expected.to eq('alive') }
    end

    context 'Dead' do
      subject(:dead) {
        described_class::Dead
      }

      it { is_expected.to eq('down') }
    end

    context 'Unknown' do
      subject(:unknown) {
        described_class::Unknown
      }

      it { is_expected.to eq('unknown') }
    end
  end
end