RSpec.describe Metasploit::Model::Search::Operation::Boolean, type: :model do
  context 'CONSTANTS' do
    context 'FORMATTED_VALUE_TO_VALUE' do
      subject(:formatted_value_to_value) do
        described_class::FORMATTED_VALUE_TO_VALUE
      end

      it "maps 'false' to false" do
        expect(formatted_value_to_value['false']).to eq(false)
      end

      it "maps 'true' to true" do
        expect(formatted_value_to_value['true']).to eq(true)
      end
    end
  end

  context 'validations' do
    it { is_expected.to allow_value(false).for(:value) }
    it { is_expected.to allow_value(true).for(:value) }
    it { is_expected.not_to allow_value(nil).for(:value) }
  end

  context '#value' do
    subject(:value) do
      operation.value
    end

    let(:operation) do
      described_class.new(:value => formatted_value)
    end

    context "with 'false'" do
      let(:formatted_value) do
        'false'
      end

      it { is_expected.to eq(false) }
    end

    context "with 'true'" do
      let(:formatted_value) do
        'true'
      end

      it { is_expected.to eq(true) }
    end

    context 'with other' do
      let(:formatted_value) do
        'unknown'
      end

      it 'should return value unparsed' do
        expect(value).to eq(formatted_value)
      end
    end
  end
end