RSpec.describe IPAddr do
  subject(:ip_address) { IPAddr.new('10.0.0.1') }
  
  describe '#==' do
    it { is_expected.to be == '10.0.0.1'}
    it { is_expected.to be == IPAddr.new('10.0.0.1')}
    it { is_expected.not_to be == 'foo'}
    
    it 'does not raise an error when compared to a non ip address' do
      expect {
        ip_address == 'foo'
      }.to_not raise_error
    end
  end
  
  describe '#include?' do
    subject(:ip_range) { IPAddr.new('10.0.0.1/24') }
    it { is_expected.to include '10.0.0.1'}
    it { is_expected.to include ip_address}
    it { is_expected.not_to include 'foo'}
    
    it 'does not raise an error when checking for a non ip address' do
      expect {
        ip_range.include? 'foo'
      }.to_not raise_error
    end
  end
  
end