RSpec.describe RubySMB::SMB1::Packet::NegotiateRequest do
  subject(:packet) { described_class.new }
  let(:dialect_string) { 'NT LM 0.12' }

  before(:each) do
    packet.add_dialect(dialect_string)
  end

  describe '#smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

    it 'should have the command set to SMB_COM_NEGOTIATE' do
      expect(header.command).to eq RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
    end

    it 'should not have the response flag set' do
      expect(header.flags.reply).to eq 0
    end
  end

  describe '#parameter_block' do
    subject(:parameter_block) { packet.parameter_block }

    it 'is a standard ParameterBlock' do
      expect(parameter_block).to be_a RubySMB::SMB1::ParameterBlock
    end
  end

  describe '#data_block' do
    subject(:data_block) { packet.data_block }

    it 'is a standard DataBlock' do
      expect(data_block).to be_a RubySMB::SMB1::DataBlock
    end

    it { is_expected.to respond_to :dialects }

    describe '#dialects' do
      it 'is an array field as per the SMB spec' do
        expect(data_block.dialects).to be_a BinData::Array
      end
    end
  end

  describe '#add_dialect' do
    it 'adds a Dialect to the packet' do
      expect { packet.add_dialect('foo') }.to change { packet.data_block.dialects.count }.by(1)
    end

    it 'uses the argument as the Dialect String' do
      packet.add_dialect('bar')
      dialects = packet.data_block.dialects.to_a
      expect(dialects.last.dialect_string).to eq 'bar'
    end
  end

  describe '#set_dialects' do
    it 'clears out any existing dialects' do
      expect { packet.set_dialects([]) }.to change { packet.data_block.dialects.count }.to(0)
    end

    it 'calls #add_dialect once for each string in the array' do
      expect(packet).to receive(:add_dialect).exactly(3).times
      packet.set_dialects(%w(foo bar baz))
    end
  end

  describe '#dialects' do
    it 'returns a ruby array of the dialect hashes' do
      expect(packet.dialects).to eq [{ buffer_format: 2, dialect_string: 'NT LM 0.12' }]
    end
  end
end
