RSpec.shared_examples_for 'Msf::Module::Privileged' do
  it { is_expected.to respond_to :privileged }
  it { is_expected.to respond_to :privileged? }
end