RSpec.describe RubySMB::SMB1::Packet::Trans::DataBlock do
  let(:data_block_class) { Class.new(described_class) }
  subject(:data_block_obj) { data_block_class.new }

  it { is_expected.to respond_to :enable_padding }
  it { is_expected.to respond_to :enable_padding= }

  it 'is a standard DataBlock' do
    expect(data_block_obj).to be_a RubySMB::SMB1::DataBlock
  end

  describe '#enable_padding' do
    it 'is true by default' do
      expect(data_block_obj.enable_padding).to be true
    end
  end

  describe '#pad1_length' do
    context 'when enable_padding is false' do
      it 'returns 0' do
        data_block_obj.enable_padding = false
        expect(data_block_obj.send(:pad1_length)).to eq(0)
      end
    end

    context 'when enable_padding is true' do
      context 'when #name field exists' do
        let(:my_name) { double('name') }

        before :example do
          data_block_class.class_exec{
            def name() end
          }
          allow(data_block_obj).to receive(:name).and_return(my_name)
          allow(data_block_obj).to receive(:respond_to?).with(:name).and_return(true)
          allow(my_name).to receive(:abs_offset).and_return(0)
          allow(my_name).to receive(:to_binary_s).and_return("")
        end

        it 'returns 0 if trans_parameters is 4-byte aligned' do
          expect(data_block_obj.send(:pad1_length)).to eq(0)
        end

        it 'returns the correct number of byte if trans_parameters is not 4-byte aligned' do
          allow(my_name).to receive(:abs_offset).and_return(1)
          expect(data_block_obj.send(:pad1_length)).to eq(3)
        end
      end

      context 'when #name field does not exist' do
        let(:byte_count) { double('byte_count') }

        before :example do
          data_block_class.class_exec{
            def byte_count() end
          }
          allow(data_block_obj).to receive(:byte_count).and_return(byte_count)
          allow(data_block_obj).to receive(:respond_to?).with(:name).and_return(false)
          allow(byte_count).to receive(:abs_offset).and_return(2)
        end

        it 'returns 0 if trans_parameters is 4-byte aligned' do
          expect(data_block_obj.send(:pad1_length)).to eq(0)
        end

        it 'returns the correct number of byte if trans_parameters is not 4-byte aligned' do
          allow(byte_count).to receive(:abs_offset).and_return(1)
          expect(data_block_obj.send(:pad1_length)).to eq(1)
        end
      end
    end
  end

  describe '#pad2_length' do
    context 'when enable_padding is false' do
      it 'returns 0' do
        data_block_obj.enable_padding = false
        expect(data_block_obj.send(:pad2_length)).to eq(0)
      end
    end

    context 'when enable_padding is true' do
      let(:trans_parameters) { double('trans_parameters') }

      before :example do
        data_block_class.class_exec{
          def trans_parameters() end
        }
        allow(data_block_obj).to receive(:trans_parameters).and_return(trans_parameters)
        allow(data_block_obj).to receive(:respond_to?).with(:name).and_return(false)
        allow(trans_parameters).to receive(:abs_offset).and_return(0)
        allow(trans_parameters).to receive(:length).and_return(0)
      end

      it 'returns 0 if trans_parameters is 4-byte aligned' do
        expect(data_block_obj.send(:pad2_length)).to eq(0)
      end

      it 'returns the correct number of byte if trans_parameters is not 4-byte aligned' do
        allow(trans_parameters).to receive(:abs_offset).and_return(1)
        expect(data_block_obj.send(:pad2_length)).to eq(3)
      end
    end
  end

  describe '#pad_name_length' do
    context 'when enable_padding is false' do
      it 'returns 0' do
        data_block_obj.enable_padding = false
        expect(data_block_obj.send(:pad_name_length)).to eq(0)
      end
    end

    context 'when enable_padding is true' do
      let(:byte_count) { double('byte_count') }

      before :example do
        data_block_class.class_exec{
          def byte_count() end
        }
        allow(data_block_obj).to receive(:byte_count).and_return(byte_count)
        allow(data_block_obj).to receive(:respond_to?).with(:name).and_return(false)
        allow(byte_count).to receive(:abs_offset).and_return(0)
      end

      it 'returns 0 if trans_parameters is 4-byte aligned' do
        expect(data_block_obj.send(:pad_name_length)).to eq(0)
      end

      it 'returns the correct number of byte if trans_parameters is not 4-byte aligned' do
        allow(byte_count).to receive(:abs_offset).and_return(1)
        expect(data_block_obj.send(:pad_name_length)).to eq(1)
      end
    end
  end
end

