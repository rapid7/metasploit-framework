RSpec.describe RubySMB::Field::NtStatus do
  subject(:nt_status) { described_class.new }

  it { is_expected.to respond_to :to_nt_status }

  it 'is a Unsigned 32-bit little endian integer' do
    expect(nt_status).to be_a BinData::Uint32le
  end

  describe '#to_nt_status' do
    it 'should return a WindowsError::ErrorCode' do
      expect(nt_status.to_nt_status).to be_a WindowsError::ErrorCode
    end

    it 'should return the correct ErrorCode' do
      expect(nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_SUCCESS
    end
  end
end
