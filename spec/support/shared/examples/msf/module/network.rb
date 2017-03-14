RSpec.shared_examples_for 'Msf::Module::Network' do
  it { is_expected.to respond_to :comm }
  it { is_expected.to respond_to :support_ipv6? }
  it { is_expected.to respond_to :target_host }
  it { is_expected.to respond_to :target_port }
end