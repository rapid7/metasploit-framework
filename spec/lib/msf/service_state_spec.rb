RSpec.describe Msf::ServiceState do
  context 'CONSTANTS' do
    context 'Closed' do
      subject(:closed) {
        described_class::Closed
      }

      it { is_expected.to eq('closed') }
    end

    context 'Filtered' do
      subject(:filtered) {
        described_class::Filtered
      }

      it { is_expected.to eq('filtered') }
    end

    context 'Open' do
      subject(:open) {
        described_class::Open
      }

      it { is_expected.to eq('open') }
    end

    context 'Unknown' do
      subject(:unknown) {
        described_class::Unknown
      }

      it { is_expected.to eq('unknown') }
    end
  end
end