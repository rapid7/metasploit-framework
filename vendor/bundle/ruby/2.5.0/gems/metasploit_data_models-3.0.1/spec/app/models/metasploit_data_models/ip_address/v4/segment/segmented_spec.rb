RSpec.describe MetasploitDataModels::IPAddress::V4::Segmented, type: :model do
  context 'CONSTANTS' do
    context 'SEGMENT_COUNT' do
      subject(:segment_count) {
        described_class::SEGMENT_COUNT
      }

      it { is_expected.to eq(4) }
    end

    context 'SEPARATOR' do
      subject(:separator) {
        described_class::SEPARATOR
      }

      it { is_expected.to eq('.') }
    end
  end

  context 'segment_count' do
    subject(:segment_count) {
      described_class.segment_count
    }

    it { is_expected.to eq(4) }
  end
end