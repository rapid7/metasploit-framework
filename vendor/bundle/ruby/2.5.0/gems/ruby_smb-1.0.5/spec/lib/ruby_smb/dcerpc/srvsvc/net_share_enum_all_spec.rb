RSpec.describe RubySMB::Dcerpc::Srvsvc::NetShareEnumAll do
  subject(:packet) { described_class.new(host: '1.2.3.4') }

  it { is_expected.to respond_to :referent_id }
  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :offset }
  it { is_expected.to respond_to :actual_count }
  it { is_expected.to respond_to :server_unc }
  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :level }
  it { is_expected.to respond_to :ctr }
  it { is_expected.to respond_to :ctr_referent_id }
  it { is_expected.to respond_to :ctr_count }
  it { is_expected.to respond_to :pointer_to_array }
  it { is_expected.to respond_to :max_buffer }
  it { is_expected.to respond_to :resume_referent_id }
  it { is_expected.to respond_to :resume_handle }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent_id' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.referent_id).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.referent_id).to eq 1
    end
  end

  describe '#max_count' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end

    it 'should be the number of unicode characters in the #server_unc field' do
      expect(packet.max_count).to eq(packet.server_unc.do_num_bytes / 2)
    end
  end

  describe '#offset' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.offset).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(packet.offset).to eq 0
    end
  end

  describe '#actual_count' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.actual_count).to be_a BinData::Uint32le
    end

    it 'should be the same value than #max_count' do
      expect(packet.actual_count).to eq(packet.max_count)
    end
  end

  describe '#server_unc' do
    it 'is a Stringz16' do
      expect(packet.server_unc).to be_a RubySMB::Field::Stringz16
    end

    it 'uses the #host parameter value to create the UNC unicode string' do
      expect(packet.server_unc).to eq("\\\\#{"1.2.3.4".encode('utf-8')}".encode('utf-16le'))
    end
  end

  describe '#pad' do
    it 'should keep #level 4-byte aligned' do
      expect(packet.level.abs_offset % 4).to eq 0
    end
  end

  describe '#level' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.level).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.level).to eq 1
    end
  end

  describe '#ctr' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.ctr).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.ctr).to eq 1
    end
  end

  describe '#ctr_referent_id' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.ctr_referent_id).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.ctr_referent_id).to eq 1
    end
  end

  describe '#ctr_count' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.ctr_count).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(packet.ctr_count).to eq 0
    end
  end

  describe '#pointer_to_array' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.pointer_to_array).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(packet.pointer_to_array).to eq 0
    end
  end

  describe '#max_buffer' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.max_buffer).to be_a BinData::Uint32le
    end

    it 'should have a default value of 4294967295' do
      expect(packet.max_buffer).to eq 4294967295
    end
  end

  describe '#resume_referent_id' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.resume_referent_id).to be_a BinData::Uint32le
    end

    it 'should have a default value of 1' do
      expect(packet.resume_referent_id).to eq 1
    end
  end

  describe '#resume_handle' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.resume_handle).to be_a BinData::Uint32le
    end

    it 'should have a default value of 0' do
      expect(packet.resume_handle).to eq 0
    end
  end

  describe '#pad_length' do
    it 'returns 0 when #level is already 4-byte aligned' do
      expect(packet.pad_length).to eq 0
    end

    it 'returns 2 when #level is only 2-byte aligned' do
      packet.server_unc = packet.server_unc + 'A'.encode('utf-16le')
      expect(packet.pad_length).to eq 2
    end
  end

  describe 'class method self.parse_response' do
    # TODO: this class method will be refactored to use proper BinData NDR
    # fields once they are ready (see https://github.com/rapid7/ruby_smb/issues/124)
  end
end


