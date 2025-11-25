RSpec.describe Rex::Proto::MsTds::MsTdsHeader do
  context 'when in its default state' do
    let(:instance) { described_class.new }

    describe '#num_bytes' do
      it 'returns the correct number of bytes' do
        expect(instance.num_bytes).to eq 8
      end
    end

    describe '#status' do
      it 'defaults to END_OF_MESSAGE' do
        expect(instance.status).to eq Rex::Proto::MsTds::MsTdsStatus::END_OF_MESSAGE
      end

      it 'is a MsTdsStatus instance' do
        expect(instance.status).to be_a Rex::Proto::MsTds::MsTdsStatus
      end
    end

    describe '#packet_type' do
      it 'is a MsTdsType instance' do
        expect(instance.packet_type).to be_a Rex::Proto::MsTds::MsTdsType
      end
    end

    describe '#packet_length' do
      it 'returns the correct length' do
        expect(instance.packet_length).to eq 8
      end
    end
  end
end