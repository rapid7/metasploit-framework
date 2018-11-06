RSpec.describe RubySMB::SMB1::BitField::HeaderFlags2 do
  subject(:flags2) { described_class.new }

  it { is_expected.to respond_to :unicode }
  it { is_expected.to respond_to :nt_status }
  it { is_expected.to respond_to :paging_io }
  it { is_expected.to respond_to :dfs }
  it { is_expected.to respond_to :extended_security }
  it { is_expected.to respond_to :reparse_path }
  it { is_expected.to respond_to :reserved1 }
  it { is_expected.to respond_to :is_long_name }
  it { is_expected.to respond_to :reserved2 }
  it { is_expected.to respond_to :signature_required }
  it { is_expected.to respond_to :compressed }
  it { is_expected.to respond_to :security_signature }
  it { is_expected.to respond_to :eas }
  it { is_expected.to respond_to :long_names }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe 'unicode' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.unicode).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags2.unicode).to eq 0
    end

    it_behaves_like 'bit field with one flag set', :unicode, 'v', 0x8000
  end

  describe 'nt_status' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.nt_status).to be_a BinData::Bit1
    end

    it 'should have a default value of 1' do
      expect(flags2.nt_status).to eq 1
    end

    it_behaves_like 'bit field with one flag set', :nt_status, 'v', 0x4000
  end

  describe 'paging_io' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.paging_io).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :paging_io, 'v', 0x2000
  end

  describe 'dfs' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.dfs).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :dfs, 'v', 0x1000
  end

  describe 'extended_security' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.extended_security).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :extended_security, 'v', 0x0800
  end

  describe 'reparse_path' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.reparse_path).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :reparse_path, 'v', 0x0400
  end

  describe 'reserved1' do
    it 'should be a 3-bit field per the SMB spec' do
      expect(flags2.reserved1).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags2.reserved1).to eq 0
    end
  end

  describe 'is_long_name' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.is_long_name).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :is_long_name, 'v', 0x0040
  end

  describe 'reserved2' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.reserved2).to be_a BinData::Bit1
    end

    it 'should have a default value of 0' do
      expect(flags2.reserved2).to eq 0
    end
  end

  describe 'signature_required' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.signature_required).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :signature_required, 'v', 0x0010
  end

  describe 'compressed' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.compressed).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :compressed, 'v', 0x0008
  end

  describe 'security_signature' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.security_signature).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :security_signature, 'v', 0x0004
  end

  describe 'eas' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.eas).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :eas, 'v', 0x0002
  end

  describe 'long_names' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flags2.long_names).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :long_names, 'v', 0x0001
  end
end
