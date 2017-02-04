RSpec.shared_examples_for 'Msf::DBManager::IPAddress' do
  it { is_expected.to respond_to :ipv46_validator }
  it { is_expected.to respond_to :ipv4_validator }
  it { is_expected.to respond_to :ipv6_validator }
  it { is_expected.to respond_to :rfc3330_reserved }
  it { is_expected.to respond_to :validate_ips }
end