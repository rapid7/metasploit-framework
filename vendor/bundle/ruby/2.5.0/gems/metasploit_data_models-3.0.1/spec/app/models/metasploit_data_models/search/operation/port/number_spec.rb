RSpec.describe MetasploitDataModels::Search::Operation::Port::Number, type: :model do
  context 'CONSTANTS' do
    context 'BITS' do
      subject(:bits) {
        described_class::BITS
      }

      it { is_expected.to eq(16) }
    end

    context 'MAXIMUM' do
      subject(:maxium) {
        described_class::MAXIMUM
      }

      it { is_expected.to eq(65535) }
    end

    context 'MINIMUM' do
      subject(:minimum) {
        described_class::MINIMUM
      }

      it { is_expected.to eq(0) }
    end

    context 'RANGE' do
      subject(:range) {
        described_class::RANGE
      }

      it { is_expected.to eq((0..65535)) }
    end
  end

  context 'validations' do
    it { is_expected.to validate_inclusion_of(:value).in_range(described_class::RANGE) }
  end
end