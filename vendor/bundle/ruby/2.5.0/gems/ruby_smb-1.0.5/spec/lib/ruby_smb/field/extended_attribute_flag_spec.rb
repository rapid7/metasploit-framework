RSpec.describe RubySMB::Field::ExtendedAttributeFlag do
  subject(:flag) { described_class.new }

  it { is_expected.to respond_to :file_need_ea }

  describe 'file_need_ea' do
    it 'should be a 1-bit field per the SMB spec' do
      expect(flag.file_need_ea).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :file_need_ea, 'C', 0x80
  end
end
